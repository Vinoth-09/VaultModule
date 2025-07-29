using System;
using Newtonsoft.Json;

namespace VaultCacheModule.Models
{
    /// <summary>
    /// Represents the authentication response from HashiCorp Vault
    /// </summary>
    public class VaultAuthResponse
    {
        [JsonProperty("auth")]
        public VaultAuth Auth { get; set; }

        [JsonProperty("lease_duration")]
        public int LeaseDuration { get; set; }

        [JsonProperty("renewable")]
        public bool Renewable { get; set; }

        [JsonProperty("lease_id")]
        public string LeaseId { get; set; }
    }

    /// <summary>
    /// Authentication details from Vault response
    /// </summary>
    public class VaultAuth
    {
        [JsonProperty("client_token")]
        public string ClientToken { get; set; }

        [JsonProperty("accessor")]
        public string Accessor { get; set; }

        [JsonProperty("policies")]
        public string[] Policies { get; set; }

        [JsonProperty("token_policies")]
        public string[] TokenPolicies { get; set; }

        [JsonProperty("metadata")]
        public object Metadata { get; set; }

        [JsonProperty("lease_duration")]
        public int LeaseDuration { get; set; }

        [JsonProperty("renewable")]
        public bool Renewable { get; set; }

        [JsonProperty("entity_id")]
        public string EntityId { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("orphan")]
        public bool Orphan { get; set; }
    }

    /// <summary>
    /// Represents a Vault secret response
    /// </summary>
    public class VaultSecretResponse
    {
        [JsonProperty("request_id")]
        public string RequestId { get; set; }

        [JsonProperty("lease_id")]
        public string LeaseId { get; set; }

        [JsonProperty("renewable")]
        public bool Renewable { get; set; }

        [JsonProperty("lease_duration")]
        public int LeaseDuration { get; set; }

        [JsonProperty("data")]
        public object Data { get; set; }

        [JsonProperty("wrap_info")]
        public object WrapInfo { get; set; }

        [JsonProperty("warnings")]
        public string[] Warnings { get; set; }

        [JsonProperty("auth")]
        public object Auth { get; set; }
    }
}
