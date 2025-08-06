using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Caching;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using VaultCacheModule.Configuration;
using VaultCacheModule.Exceptions;
using VaultCacheModule.Models;
using Timer = System.Timers.Timer;

namespace VaultCacheModule
{
    /// <summary>
    /// Singleton cache for HashiCorp Vault secrets that works across multiple app domains using MemoryCache
    /// </summary>
    public sealed class VaultSecretCache : MarshalByRefObject, IVaultSecretCache, IDisposable
    {
        private static readonly object _lockObject = new object();
        private static volatile VaultSecretCache _instance;
        private static VaultConfiguration _configuration;
        private static VaultClient _vaultClient;

        private readonly MemoryCache _memoryCache;
        private readonly ConcurrentDictionary<string, bool> _secretPaths;
        private readonly Timer _refreshTimer;
        private readonly object _refreshLock = new object();
        private bool _disposed = false;

        // Cache key prefix to avoid conflicts
        private const string SECRET_KEY_PREFIX = "vault_secret_";

        public DateTime? LastRefreshTime { get; private set; }
        public DateTime? NextRefreshTime { get; private set; }

        public event EventHandler<SecretRefreshEventArgs> SecretsRefreshed;
        public event EventHandler<SecretRefreshErrorEventArgs> RefreshError;

        /// <summary>
        /// Private constructor for singleton pattern
        /// </summary>
        private VaultSecretCache()
        {
            _memoryCache = new MemoryCache("VaultSecretCache");
            _secretPaths = new ConcurrentDictionary<string, bool>();
            
            // Set up the refresh timer
            _refreshTimer = new Timer();
            _refreshTimer.Elapsed += OnRefreshTimerElapsed;
            _refreshTimer.AutoReset = true;
        }

        /// <summary>
        /// Gets the singleton instance of the VaultSecretCache
        /// </summary>
        /// <param name="configuration">Vault configuration (required for first initialization)</param>
        /// <returns>The singleton cache instance</returns>
        public static VaultSecretCache GetInstance(VaultConfiguration configuration = null)
        {
            if (_instance == null)
            {
                lock (_lockObject)
                {
                    if (_instance == null)
                    {
                        if (configuration == null)
                        {
                            throw new ArgumentException("Configuration is required for first-time initialization", nameof(configuration));
                        }

                        _configuration = configuration;
                        _vaultClient = new VaultClient(configuration);
                        _instance = new VaultSecretCache();
                        
                        // Set up the refresh timer interval
                        _instance._refreshTimer.Interval = _configuration.CacheRefreshInterval.TotalMilliseconds;
                    }
                }
            }

            return _instance;
        }

        /// <summary>
        /// Override to ensure the singleton persists across app domain boundaries
        /// </summary>
        /// <returns>null to indicate the object should live forever</returns>
        public override object InitializeLifetimeService()
        {
            return null;
        }

        /// <summary>
        /// Initializes the cache with the specified secret paths
        /// </summary>
        public async Task InitializeAsync(IEnumerable<string> secretPaths)
        {
            if (secretPaths == null)
            {
                throw new ArgumentNullException(nameof(secretPaths));
            }

            var pathList = secretPaths.ToList();
            if (!pathList.Any())
            {
                throw new ArgumentException("At least one secret path must be provided", nameof(secretPaths));
            }

            // Add all paths to our tracking dictionary
            foreach (var path in pathList)
            {
                _secretPaths.TryAdd(path, true);
            }

            // Perform initial load of all secrets
            await RefreshAllSecretsAsync();

            // Start the refresh timer
            _refreshTimer.Start();
            NextRefreshTime = DateTime.UtcNow.Add(_configuration.CacheRefreshInterval);
        }

        /// <summary>
        /// Gets a secret from the cache by path
        /// </summary>
        public VaultSecret GetSecret(string secretPath)
        {
            if (string.IsNullOrWhiteSpace(secretPath))
            {
                return null;
            }

            var cacheKey = GetSecretCacheKey(secretPath);
            var secret = _memoryCache.Get(cacheKey) as VaultSecret;
            
            // If secret is not in cache or has expired, try to refresh it
            if (secret == null || secret.IsExpired())
            {
                // Try to refresh the secret asynchronously (fire and forget)
                Task.Run(async () =>
                {
                    try
                    {
                        await RefreshSecretAsync(secretPath);
                    }
                    catch (Exception ex)
                    {
                        OnRefreshError(secretPath, ex);
                    }
                });
                
                // Return the expired secret if we have one, or null if not
                return secret;
            }

            return secret;
        }

        /// <summary>
        /// Gets a specific value from a cached secret
        /// </summary>
        public string GetSecretValue(string secretPath, string key)
        {
            var secret = GetSecret(secretPath);
            return secret?.GetStringValue(key);
        }

        /// <summary>
        /// Gets all cached secrets
        /// </summary>
        public Dictionary<string, VaultSecret> GetAllSecrets()
        {
            var secrets = new Dictionary<string, VaultSecret>();
            
            foreach (var secretPath in _secretPaths.Keys)
            {
                var cacheKey = GetSecretCacheKey(secretPath);
                var secret = _memoryCache.Get(cacheKey) as VaultSecret;
                if (secret != null)
                {
                    secrets[secretPath] = secret;
                }
            }
            
            return secrets;
        }

        /// <summary>
        /// Manually refreshes a specific secret from Vault
        /// </summary>
        public async Task RefreshSecretAsync(string secretPath)
        {
            if (string.IsNullOrWhiteSpace(secretPath))
            {
                throw new ArgumentException("Secret path cannot be null or empty", nameof(secretPath));
            }

            try
            {
                var secret = await _vaultClient.GetSecretAsync(secretPath);
                var cacheKey = GetSecretCacheKey(secretPath);
                
                // Create cache policy with proper expiration
                var cachePolicy = new CacheItemPolicy
                {
                    AbsoluteExpiration = secret.ExpiresAt,
                    Priority = CacheItemPriority.High,
                    RemovedCallback = OnSecretRemovedFromCache
                };
                
                _memoryCache.Set(cacheKey, secret, cachePolicy);
            }
            catch (Exception ex)
            {
                OnRefreshError(secretPath, ex);
                throw;
            }
        }

        /// <summary>
        /// Manually refreshes all cached secrets from Vault
        /// </summary>
        public async Task RefreshAllSecretsAsync()
        {
            if (!_secretPaths.Any())
            {
                return;
            }

            lock (_refreshLock)
            {
                // Prevent concurrent refresh operations
                if (DateTime.UtcNow.Subtract(LastRefreshTime ?? DateTime.MinValue).TotalSeconds < 30)
                {
                    return; // Skip if we just refreshed within the last 30 seconds
                }
            }

            var refreshedPaths = new List<string>();

            try
            {
                var secrets = await _vaultClient.GetSecretsAsync(_secretPaths.Keys);
                
                foreach (var kvp in secrets)
                {
                    var cacheKey = GetSecretCacheKey(kvp.Key);
                    var secret = kvp.Value;
                    
                    // Create cache policy with proper expiration
                    var cachePolicy = new CacheItemPolicy
                    {
                        AbsoluteExpiration = secret.ExpiresAt,
                        Priority = CacheItemPriority.High,
                        RemovedCallback = OnSecretRemovedFromCache
                    };
                    
                    _memoryCache.Set(cacheKey, secret, cachePolicy);
                    refreshedPaths.Add(kvp.Key);
                }

                LastRefreshTime = DateTime.UtcNow;
                NextRefreshTime = LastRefreshTime.Value.Add(_configuration.CacheRefreshInterval);

                OnSecretsRefreshed(refreshedPaths);
            }
            catch (Exception ex)
            {
                OnRefreshError(null, ex);
                throw;
            }
        }

        /// <summary>
        /// Adds a new secret path to be cached
        /// </summary>
        public async Task AddSecretPathAsync(string secretPath)
        {
            if (string.IsNullOrWhiteSpace(secretPath))
            {
                throw new ArgumentException("Secret path cannot be null or empty", nameof(secretPath));
            }

            _secretPaths.TryAdd(secretPath, true);
            await RefreshSecretAsync(secretPath);
        }

        /// <summary>
        /// Removes a secret from the cache
        /// </summary>
        public bool RemoveSecret(string secretPath)
        {
            if (string.IsNullOrWhiteSpace(secretPath))
            {
                return false;
            }

            _secretPaths.TryRemove(secretPath, out _);
            
            var cacheKey = GetSecretCacheKey(secretPath);
            var removed = _memoryCache.Remove(cacheKey);
            
            return removed != null;
        }

        /// <summary>
        /// Timer event handler for automatic refresh
        /// </summary>
        private async void OnRefreshTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try
            {
                await RefreshAllSecretsAsync();
            }
            catch (Exception ex)
            {
                OnRefreshError(null, ex);
            }
        }

        /// <summary>
        /// Callback when a secret is removed from cache (due to expiration or eviction)
        /// </summary>
        private void OnSecretRemovedFromCache(CacheEntryRemovedArguments arguments)
        {
            if (arguments.RemovedReason == CacheEntryRemovedReason.Expired)
            {
                // Secret expired - extract the secret path from cache key
                var secretPath = GetSecretPathFromCacheKey(arguments.CacheItem.Key);
                
                // Optionally trigger background refresh for expired secrets if they're still tracked
                if (!string.IsNullOrEmpty(secretPath) && _secretPaths.ContainsKey(secretPath))
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            await RefreshSecretAsync(secretPath);
                        }
                        catch (Exception ex)
                        {
                            OnRefreshError(secretPath, ex);
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Generates cache key for a secret path
        /// </summary>
        private string GetSecretCacheKey(string secretPath)
        {
            return SECRET_KEY_PREFIX + secretPath;
        }

        /// <summary>
        /// Extracts secret path from cache key
        /// </summary>
        private string GetSecretPathFromCacheKey(string cacheKey)
        {
            return cacheKey?.StartsWith(SECRET_KEY_PREFIX) == true 
                ? cacheKey.Substring(SECRET_KEY_PREFIX.Length) 
                : null;
        }

        /// <summary>
        /// Raises the SecretsRefreshed event
        /// </summary>
        private void OnSecretsRefreshed(List<string> refreshedPaths)
        {
            SecretsRefreshed?.Invoke(this, new SecretRefreshEventArgs
            {
                RefreshTime = DateTime.UtcNow,
                SecretCount = refreshedPaths.Count,
                RefreshedPaths = refreshedPaths
            });
        }

        /// <summary>
        /// Raises the RefreshError event
        /// </summary>
        private void OnRefreshError(string secretPath, Exception exception)
        {
            RefreshError?.Invoke(this, new SecretRefreshErrorEventArgs
            {
                ErrorTime = DateTime.UtcNow,
                Exception = exception,
                SecretPath = secretPath
            });
        }

        /// <summary>
        /// Disposes the cache and its resources
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _refreshTimer?.Stop();
                _refreshTimer?.Dispose();
                _memoryCache?.Dispose();
                _vaultClient?.Dispose();
                _disposed = true;
            }
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~VaultSecretCache()
        {
            Dispose();
        }
    }
}
