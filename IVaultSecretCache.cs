using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using VaultCacheModule.Models;

namespace VaultCacheModule
{
    /// <summary>
    /// Interface for the Vault secret cache
    /// </summary>
    public interface IVaultSecretCache
    {
        /// <summary>
        /// Initializes the cache with the specified secret paths
        /// </summary>
        /// <param name="secretPaths">The paths to secrets that should be cached</param>
        /// <returns>Task representing the initialization operation</returns>
        Task InitializeAsync(IEnumerable<string> secretPaths);

        /// <summary>
        /// Gets a secret from the cache by path
        /// </summary>
        /// <param name="secretPath">The path to the secret</param>
        /// <returns>The cached secret, or null if not found</returns>
        VaultSecret GetSecret(string secretPath);

        /// <summary>
        /// Gets a specific value from a cached secret
        /// </summary>
        /// <param name="secretPath">The path to the secret</param>
        /// <param name="key">The key within the secret data</param>
        /// <returns>The value if found, null otherwise</returns>
        string GetSecretValue(string secretPath, string key);

        /// <summary>
        /// Gets all cached secrets
        /// </summary>
        /// <returns>Dictionary of all cached secrets</returns>
        Dictionary<string, VaultSecret> GetAllSecrets();

        /// <summary>
        /// Manually refreshes a specific secret from Vault
        /// </summary>
        /// <param name="secretPath">The path to the secret to refresh</param>
        /// <returns>Task representing the refresh operation</returns>
        Task RefreshSecretAsync(string secretPath);

        /// <summary>
        /// Manually refreshes all cached secrets from Vault
        /// </summary>
        /// <returns>Task representing the refresh operation</returns>
        Task RefreshAllSecretsAsync();

        /// <summary>
        /// Adds a new secret path to be cached
        /// </summary>
        /// <param name="secretPath">The path to the secret</param>
        /// <returns>Task representing the operation</returns>
        Task AddSecretPathAsync(string secretPath);

        /// <summary>
        /// Removes a secret from the cache
        /// </summary>
        /// <param name="secretPath">The path to the secret to remove</param>
        /// <returns>True if the secret was removed, false if it wasn't found</returns>
        bool RemoveSecret(string secretPath);

        /// <summary>
        /// Gets the last refresh time for all secrets
        /// </summary>
        /// <returns>The timestamp of the last successful refresh</returns>
        DateTime? LastRefreshTime { get; }

        /// <summary>
        /// Gets the next scheduled refresh time
        /// </summary>
        /// <returns>The timestamp of the next scheduled refresh</returns>
        DateTime? NextRefreshTime { get; }

        /// <summary>
        /// Event fired when secrets are refreshed
        /// </summary>
        event EventHandler<SecretRefreshEventArgs> SecretsRefreshed;

        /// <summary>
        /// Event fired when a refresh operation fails
        /// </summary>
        event EventHandler<SecretRefreshErrorEventArgs> RefreshError;
    }

    /// <summary>
    /// Event arguments for secret refresh events
    /// </summary>
    public class SecretRefreshEventArgs : EventArgs
    {
        public DateTime RefreshTime { get; set; }
        public int SecretCount { get; set; }
        public List<string> RefreshedPaths { get; set; }

        public SecretRefreshEventArgs()
        {
            RefreshedPaths = new List<string>();
        }
    }

    /// <summary>
    /// Event arguments for secret refresh error events
    /// </summary>
    public class SecretRefreshErrorEventArgs : EventArgs
    {
        public DateTime ErrorTime { get; set; }
        public Exception Exception { get; set; }
        public string SecretPath { get; set; }
    }
}
