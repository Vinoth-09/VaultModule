using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Cert;
using VaultSharp.V1.Commons;
using VaultCacheModule.Configuration;
using VaultCacheModule.Exceptions;
using VaultCacheModule.Models;

namespace VaultCacheModule
{
    /// <summary>
    /// Client for interacting with HashiCorp Vault using VaultSharp with TLS certificate authentication
    /// </summary>
    public class VaultClient : IDisposable
    {
        private readonly VaultConfiguration _configuration;
        private readonly IVaultClient _vaultSharpClient;
        private readonly object _authLock = new object();
        private bool _disposed = false;

        public VaultClient(VaultConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            
            if (!_configuration.IsValid())
            {
                throw new ArgumentException("Invalid Vault configuration", nameof(configuration));
            }

            _vaultSharpClient = CreateVaultSharpClient();
        }

        /// <summary>
        /// Creates and configures the VaultSharp client with TLS certificate authentication
        /// </summary>
        private IVaultClient CreateVaultSharpClient()
        {
            try
            {
                // Configure TLS certificate authentication
                var certAuthMethodInfo = new CertAuthMethodInfo(_configuration.RoleName)
                {
                    MountPoint = _configuration.CertAuthPath,
                    ClientCertificate = _configuration.ClientCertificate
                };

                // Create VaultSharp client settings
                var vaultClientSettings = new VaultClientSettings(_configuration.VaultUrl, certAuthMethodInfo)
                {
                    VaultServiceTimeout = _configuration.RequestTimeout,
                    UseVaultTokenHeaderInsteadOfAuthorizationHeader = true
                };

                // Configure HTTP client handler for additional TLS settings
                var httpClientHandler = new HttpClientHandler();
                httpClientHandler.ClientCertificates.Add(_configuration.ClientCertificate);
                
                // In production, implement proper certificate validation
                httpClientHandler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    // TODO: Implement proper server certificate validation for production
                    return true;
                };

                vaultClientSettings.MyHttpClientProviderFunc = () => new HttpClient(httpClientHandler)
                {
                    Timeout = _configuration.RequestTimeout
                };

                return new VaultClient(vaultClientSettings);
            }
            catch (Exception ex)
            {
                throw new VaultException("Failed to create VaultSharp client", ex);
            }
        }

        /// <summary>
        /// Authenticates with Vault using TLS certificate authentication
        /// This is handled automatically by VaultSharp, but we expose it for explicit authentication
        /// </summary>
        public async Task<bool> AuthenticateAsync()
        {
            try
            {
                // VaultSharp handles authentication automatically, but we can test it
                // by making a simple request to verify connectivity and authentication
                var healthStatus = await _vaultSharpClient.V1.System.GetHealthStatusAsync();
                return healthStatus != null;
            }
            catch (Exception ex)
            {
                throw new VaultException("TLS Certificate authentication failed", ex);
            }
        }

        /// <summary>
        /// Retrieves a secret from the specified path in Vault
        /// </summary>
        /// <param name="secretPath">The path to the secret in Vault</param>
        /// <returns>The secret data</returns>
        public async Task<VaultSecret> GetSecretAsync(string secretPath)
        {
            if (string.IsNullOrWhiteSpace(secretPath))
            {
                throw new ArgumentException("Secret path cannot be null or empty", nameof(secretPath));
            }

            var attempts = 0;
            while (attempts < _configuration.MaxRetryAttempts)
            {
                try
                {
                    // Parse the secret path to determine the mount and path
                    var pathParts = secretPath.TrimStart('/').Split('/');
                    if (pathParts.Length < 2)
                    {
                        throw new ArgumentException($"Invalid secret path format: {secretPath}. Expected format: 'mount/path'");
                    }

                    var mountPoint = pathParts[0];
                    var path = string.Join("/", pathParts, 1, pathParts.Length - 1);

                    Secret<SecretData> vaultSecret;

                    // Try KV v2 first, then fall back to KV v1
                    try
                    {
                        // KV v2 format
                        vaultSecret = await _vaultSharpClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path, mountPoint: mountPoint);
                    }
                    catch
                    {
                        // Fall back to KV v1 format
                        vaultSecret = await _vaultSharpClient.V1.Secrets.KeyValue.V1.ReadSecretAsync(path, mountPoint);
                    }

                    if (vaultSecret?.Data?.Data == null)
                    {
                        throw new VaultException($"No data found at secret path: {secretPath}");
                    }

                    var secret = new VaultSecret
                    {
                        Path = secretPath,
                        RetrievedAt = DateTime.UtcNow,
                        ExpiresAt = DateTime.UtcNow.Add(_configuration.CacheRefreshInterval),
                        LeaseDuration = vaultSecret.LeaseDurationSeconds,
                        Renewable = vaultSecret.Renewable,
                        LeaseId = vaultSecret.LeaseId,
                        Data = new Dictionary<string, object>(vaultSecret.Data.Data)
                    };

                    return secret;
                }
                catch (VaultApiException vaultEx)
                {
                    if (vaultEx.HttpStatusCode == 403 || vaultEx.HttpStatusCode == 401)
                    {
                        // Authentication issue - VaultSharp should handle re-auth automatically
                        attempts++;
                        if (attempts >= _configuration.MaxRetryAttempts)
                        {
                            throw new VaultException($"Authentication failed for secret path '{secretPath}' after {attempts} attempts", vaultEx);
                        }
                        await Task.Delay(_configuration.RetryDelay);
                        continue;
                    }

                    throw new VaultException($"Vault API error retrieving secret from path '{secretPath}': {vaultEx.Message}", vaultEx);
                }
                catch (VaultException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    attempts++;
                    if (attempts >= _configuration.MaxRetryAttempts)
                    {
                        throw new VaultException($"Failed to retrieve secret after {attempts} attempts", ex);
                    }

                    await Task.Delay(_configuration.RetryDelay);
                }
            }

            throw new VaultException($"Failed to retrieve secret after {_configuration.MaxRetryAttempts} attempts");
        }

        /// <summary>
        /// Retrieves multiple secrets from the specified paths
        /// </summary>
        /// <param name="secretPaths">The paths to the secrets in Vault</param>
        /// <returns>Dictionary of secret paths and their data</returns>
        public async Task<Dictionary<string, VaultSecret>> GetSecretsAsync(IEnumerable<string> secretPaths)
        {
            if (secretPaths == null)
            {
                throw new ArgumentNullException(nameof(secretPaths));
            }

            var results = new Dictionary<string, VaultSecret>();
            var tasks = new List<Task>();

            foreach (var path in secretPaths)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var secret = await GetSecretAsync(path);
                        lock (results)
                        {
                            results[path] = secret;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log error but continue with other secrets
                        // In a real implementation, you might want to use a proper logging framework
                        System.Diagnostics.Debug.WriteLine($"Failed to retrieve secret from path '{path}': {ex.Message}");
                    }
                }));
            }

            await Task.WhenAll(tasks);
            return results;
        }

        /// <summary>
        /// Gets the Vault health status
        /// </summary>
        /// <returns>Health status information</returns>
        public async Task<bool> GetHealthStatusAsync()
        {
            try
            {
                var healthStatus = await _vaultSharpClient.V1.System.GetHealthStatusAsync();
                return healthStatus?.Initialized == true && healthStatus?.Sealed == false;
            }
            catch (Exception ex)
            {
                throw new VaultException("Failed to get Vault health status", ex);
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _vaultSharpClient?.Dispose();
                _disposed = true;
            }
        }
    }
}
