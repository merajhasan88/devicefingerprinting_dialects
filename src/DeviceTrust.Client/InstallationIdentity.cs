using System;
using DeviceTrust.Client.Keys;

namespace DeviceTrust.Client
{
    /// <summary>
    /// This installation: its UUID and the device-bound key that speaks for it.
    /// </summary>
    /// <remarks>
    /// The UUID is a convenience. The server's authoritative identity is
    /// <see cref="KeyThumbprint"/>, which is why re-registering the same key
    /// under a different UUID returns the original installation, and why a UUID
    /// reused with a different key is rejected as a collision.
    /// </remarks>
    public sealed class InstallationIdentity
    {
        /// <summary>Creates an identity.</summary>
        public InstallationIdentity(string installationId, InstallationKeyMetadata key)
        {
            InstallationId = installationId ?? throw new ArgumentNullException(nameof(installationId));
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        /// <summary>The installation UUID currently in use.</summary>
        public string InstallationId { get; }

        /// <summary>What the key store reports about the installation key.</summary>
        public InstallationKeyMetadata Key { get; }

        /// <summary>The RFC 7638 thumbprint the server uses as the real identity.</summary>
        public string KeyThumbprint => Key.PublicKey.Thumbprint;

        /// <summary>Returns the same identity under the canonical installation id the server returned.</summary>
        public InstallationIdentity WithInstallationId(string installationId)
        {
            return new InstallationIdentity(installationId, Key);
        }
    }
}
