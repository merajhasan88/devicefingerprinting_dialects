using System;

namespace DeviceTrust.Client.Storage
{
    /// <summary>
    /// The non-secret local state a client keeps between launches.
    /// </summary>
    /// <remarks>
    /// The private key is deliberately absent. It lives in the OS key store and
    /// never crosses into this record, so persisting this state — even
    /// carelessly — cannot leak the device binding. What is here is the opaque
    /// installation UUID and the issued tokens, which are useless on another
    /// device without a signature from the key that stayed behind.
    /// </remarks>
    public sealed class InstallationState
    {
        /// <summary>The client-chosen installation UUID, or the canonical one the server returned.</summary>
        public string? InstallationId { get; set; }

        /// <summary>The device id the server assigned, cached for display.</summary>
        public string? DeviceId { get; set; }

        /// <summary>The key thumbprint last registered, cached for display.</summary>
        public string? KeyThumbprint { get; set; }

        /// <summary>The account id of the stored session.</summary>
        public string? AccountId { get; set; }

        /// <summary>The stored access token.</summary>
        public string? AccessToken { get; set; }

        /// <summary>The stored refresh token.</summary>
        public string? RefreshToken { get; set; }

        /// <summary>When this record was last written, for diagnostics.</summary>
        public DateTimeOffset? UpdatedAt { get; set; }
    }
}
