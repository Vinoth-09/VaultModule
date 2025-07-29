using System;
using System.Security.Cryptography.X509Certificates;

namespace VaultCacheModule.Configuration
{
    /// <summary>
    /// Configuration class for HashiCorp Vault connection settings
    /// </summary>
    public class VaultConfiguration
    {
        /// <summary>
        /// The base URL of the Vault server (e.g., https://vault.company.com:8200)
        /// </summary>
        public string VaultUrl { get; set; }

        /// <summary>
        /// The certificate authentication mount path (default: cert)
        /// </summary>
        public string CertAuthPath { get; set; } = "cert";

        /// <summary>
        /// The role name configured in Vault for certificate authentication
        /// </summary>
        public string RoleName { get; set; }

        /// <summary>
        /// The client certificate for TLS authentication
        /// </summary>
        public X509Certificate2 ClientCertificate { get; set; }

        /// <summary>
        /// Timeout for HTTP requests to Vault (default: 30 seconds)
        /// </summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Cache refresh interval (default: 24 hours)
        /// </summary>
        public TimeSpan CacheRefreshInterval { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Maximum number of retry attempts for failed requests
        /// </summary>
        public int MaxRetryAttempts { get; set; } = 3;

        /// <summary>
        /// Delay between retry attempts
        /// </summary>
        public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Validates the configuration settings
        /// </summary>
        /// <returns>True if configuration is valid</returns>
        public bool IsValid()
        {
            return !string.IsNullOrWhiteSpace(VaultUrl) &&
                   !string.IsNullOrWhiteSpace(RoleName) &&
                   ClientCertificate != null &&
                   RequestTimeout > TimeSpan.Zero &&
                   CacheRefreshInterval > TimeSpan.Zero;
        }
    }
}
