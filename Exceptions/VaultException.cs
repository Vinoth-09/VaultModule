using System;

namespace VaultCacheModule.Exceptions
{
    /// <summary>
    /// Custom exception for HashiCorp Vault related errors
    /// </summary>
    public class VaultException : Exception
    {
        /// <summary>
        /// HTTP status code from Vault response (if applicable)
        /// </summary>
        public int? StatusCode { get; }

        /// <summary>
        /// The Vault error response content
        /// </summary>
        public string VaultErrorContent { get; }

        public VaultException() : base()
        {
        }

        public VaultException(string message) : base(message)
        {
        }

        public VaultException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public VaultException(string message, int statusCode, string vaultErrorContent = null) 
            : base(message)
        {
            StatusCode = statusCode;
            VaultErrorContent = vaultErrorContent;
        }

        public VaultException(string message, int statusCode, string vaultErrorContent, Exception innerException) 
            : base(message, innerException)
        {
            StatusCode = statusCode;
            VaultErrorContent = vaultErrorContent;
        }

        public override string ToString()
        {
            var result = base.ToString();
            
            if (StatusCode.HasValue)
            {
                result += $"\nHTTP Status Code: {StatusCode}";
            }
            
            if (!string.IsNullOrEmpty(VaultErrorContent))
            {
                result += $"\nVault Error Content: {VaultErrorContent}";
            }
            
            return result;
        }
    }
}
