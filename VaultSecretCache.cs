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
    /// Singleton cache for HashiCorp Vault secrets that works across multiple app domains
    /// </summary>
    public sealed class VaultSecretCache : MarshalByRefObject, IVaultSecretCache, IDisposable
    {
        private static readonly object _lockObject = new object();
        private static volatile VaultSecretCache _instance;
        private static VaultConfiguration _configuration;
        private static VaultClient _vaultClient;

        private readonly ConcurrentDictionary<string, VaultSecret> _secretCache;
        private readonly ConcurrentDictionary<string, bool> _secretPaths;
        private readonly Timer _refreshTimer;
        private readonly object _refreshLock = new object();
        private bool _disposed = false;

        public DateTime? LastRefreshTime { get; private set; }
        public DateTime? NextRefreshTime { get; private set; }

        public event EventHandler<SecretRefreshEventArgs> SecretsRefreshed;
        public event EventHandler<SecretRefreshErrorEventArgs> RefreshError;

        /// <summary>
        /// Private constructor for singleton pattern
        /// </summary>
        private VaultSecretCache()
        {
            _secretCache = new ConcurrentDictionary<string, VaultSecret>();
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

            _secretCache.TryGetValue(secretPath, out var secret);
            
            // Check if the secret has expired
            if (secret != null && secret.IsExpired())
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
            return new Dictionary<string, VaultSecret>(_secretCache);
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
                _secretCache.AddOrUpdate(secretPath, secret, (key, oldValue) => secret);
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
            var errors = new List<Exception>();

            try
            {
                var secrets = await _vaultClient.GetSecretsAsync(_secretPaths.Keys);
                
                foreach (var kvp in secrets)
                {
                    _secretCache.AddOrUpdate(kvp.Key, kvp.Value, (key, oldValue) => kvp.Value);
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
            return _secretCache.TryRemove(secretPath, out _);
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
