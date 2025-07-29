using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VaultCacheModule.Configuration;
using VaultCacheModule.Exceptions;
using VaultCacheModule.Models;

namespace VaultCacheModule
{
    /// <summary>
    /// Client for interacting with HashiCorp Vault using TLS certificate authentication
    /// </summary>
    public class VaultClient : IDisposable
    {
        private readonly VaultConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private string _authToken;
        private DateTime _tokenExpiry;
        private readonly object _authLock = new object();
        private bool _disposed = false;

        public VaultClient(VaultConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            
            if (!_configuration.IsValid())
            {
                throw new ArgumentException("Invalid Vault configuration", nameof(configuration));
            }

            _httpClient = CreateHttpClient();
        }

        /// <summary>
        /// Creates and configures the HTTP client with TLS certificate authentication
        /// </summary>
        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();
            
            // Add the client certificate for TLS authentication
            handler.ClientCertificates.Add(_configuration.ClientCertificate);
            
            // Configure SSL/TLS settings
            handler.ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                // In production, you should implement proper certificate validation
                // For now, we'll accept all certificates (modify as needed for your security requirements)
                return true;
            };

            var client = new HttpClient(handler)
            {
                BaseAddress = new Uri(_configuration.VaultUrl),
                Timeout = _configuration.RequestTimeout
            };

            client.DefaultRequestHeaders.Add("X-Vault-Request", "true");
            
            return client;
        }

        /// <summary>
        /// Authenticates with Vault using TLS certificate authentication
        /// </summary>
        public async Task<bool> AuthenticateAsync()
        {
            try
            {
                var authPath = $"/v1/auth/{_configuration.CertAuthPath}/login";
                var authPayload = new
                {
                    name = _configuration.RoleName
                };

                var json = JsonConvert.SerializeObject(authPayload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(authPath, content);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    throw new VaultException(
                        $"Authentication failed: {response.ReasonPhrase}",
                        (int)response.StatusCode,
                        responseContent);
                }

                var authResponse = JsonConvert.DeserializeObject<VaultAuthResponse>(responseContent);
                
                if (authResponse?.Auth?.ClientToken == null)
                {
                    throw new VaultException("Authentication response did not contain a valid token");
                }

                lock (_authLock)
                {
                    _authToken = authResponse.Auth.ClientToken;
                    _tokenExpiry = DateTime.UtcNow.AddSeconds(authResponse.Auth.LeaseDuration - 60); // Refresh 1 minute early
                }

                // Set the token for future requests
                _httpClient.DefaultRequestHeaders.Remove("X-Vault-Token");
                _httpClient.DefaultRequestHeaders.Add("X-Vault-Token", _authToken);

                return true;
            }
            catch (Exception ex) when (!(ex is VaultException))
            {
                throw new VaultException("Authentication failed", ex);
            }
        }

        /// <summary>
        /// Ensures the client is authenticated and the token is valid
        /// </summary>
        private async Task EnsureAuthenticatedAsync()
        {
            lock (_authLock)
            {
                if (!string.IsNullOrEmpty(_authToken) && DateTime.UtcNow < _tokenExpiry)
                {
                    return;
                }
            }

            await AuthenticateAsync();
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

            await EnsureAuthenticatedAsync();

            var attempts = 0;
            while (attempts < _configuration.MaxRetryAttempts)
            {
                try
                {
                    var response = await _httpClient.GetAsync($"/v1/{secretPath.TrimStart('/')}");
                    var responseContent = await response.Content.ReadAsStringAsync();

                    if (!response.IsSuccessStatusCode)
                    {
                        if (response.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                            response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        {
                            // Token might be expired, try to re-authenticate
                            await AuthenticateAsync();
                            attempts++;
                            continue;
                        }

                        throw new VaultException(
                            $"Failed to retrieve secret from path '{secretPath}': {response.ReasonPhrase}",
                            (int)response.StatusCode,
                            responseContent);
                    }

                    var secretResponse = JsonConvert.DeserializeObject<VaultSecretResponse>(responseContent);
                    
                    var secret = new VaultSecret
                    {
                        Path = secretPath,
                        RetrievedAt = DateTime.UtcNow,
                        ExpiresAt = DateTime.UtcNow.Add(_configuration.CacheRefreshInterval),
                        LeaseDuration = secretResponse.LeaseDuration,
                        Renewable = secretResponse.Renewable,
                        LeaseId = secretResponse.LeaseId
                    };

                    // Handle different data formats (KV v1 vs v2)
                    if (secretResponse.Data is Newtonsoft.Json.Linq.JObject dataObj)
                    {
                        // Check if this is KV v2 format (data.data)
                        if (dataObj.ContainsKey("data") && dataObj["data"] is Newtonsoft.Json.Linq.JObject)
                        {
                            secret.Data = dataObj["data"].ToObject<Dictionary<string, object>>();
                        }
                        else
                        {
                            // KV v1 format
                            secret.Data = dataObj.ToObject<Dictionary<string, object>>();
                        }
                    }

                    return secret;
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

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _disposed = true;
            }
        }
    }
}
