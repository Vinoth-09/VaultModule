using System;
using System.Collections.Generic;

namespace VaultCacheModule.Models
{
    /// <summary>
    /// Represents a secret retrieved from HashiCorp Vault
    /// </summary>
    public class VaultSecret
    {
        /// <summary>
        /// The path of the secret in Vault
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// The secret data as key-value pairs
        /// </summary>
        public Dictionary<string, object> Data { get; set; }

        /// <summary>
        /// When the secret was retrieved from Vault
        /// </summary>
        public DateTime RetrievedAt { get; set; }

        /// <summary>
        /// When the secret expires and should be refreshed
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// The lease duration in seconds (if applicable)
        /// </summary>
        public int? LeaseDuration { get; set; }

        /// <summary>
        /// Whether the secret is renewable
        /// </summary>
        public bool Renewable { get; set; }

        /// <summary>
        /// The lease ID for renewable secrets
        /// </summary>
        public string LeaseId { get; set; }

        public VaultSecret()
        {
            Data = new Dictionary<string, object>();
            RetrievedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Checks if the secret has expired and needs to be refreshed
        /// </summary>
        /// <returns>True if the secret has expired</returns>
        public bool IsExpired()
        {
            return DateTime.UtcNow >= ExpiresAt;
        }

        /// <summary>
        /// Gets a specific value from the secret data
        /// </summary>
        /// <param name="key">The key to retrieve</param>
        /// <returns>The value if found, null otherwise</returns>
        public object GetValue(string key)
        {
            return Data.TryGetValue(key, out var value) ? value : null;
        }

        /// <summary>
        /// Gets a specific value from the secret data as a string
        /// </summary>
        /// <param name="key">The key to retrieve</param>
        /// <returns>The value as string if found, null otherwise</returns>
        public string GetStringValue(string key)
        {
            return GetValue(key)?.ToString();
        }
    }
}
