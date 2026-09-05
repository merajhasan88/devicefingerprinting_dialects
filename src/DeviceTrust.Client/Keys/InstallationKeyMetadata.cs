using System;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// What a key store reports about the key it is holding.
    /// </summary>
    /// <remarks>
    /// These fields exist so an operator can tell, from the client, whether the
    /// key really is held by hardware. They are local self-description and are
    /// deliberately not sent to the server as a security claim: the server does
    /// not trust a client's assertion about its own security level, and there is
    /// no remote key attestation in this design.
    /// </remarks>
    public sealed class InstallationKeyMetadata
    {
        /// <summary>Creates key metadata.</summary>
        public InstallationKeyMetadata(
            EcPublicJsonWebKey publicKey,
            string keyAlias,
            string provider,
            string securityLevel,
            bool hardwareBacked,
            bool privateKeyExportable,
            bool created)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            KeyAlias = keyAlias ?? throw new ArgumentNullException(nameof(keyAlias));
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
            SecurityLevel = securityLevel ?? throw new ArgumentNullException(nameof(securityLevel));
            HardwareBacked = hardwareBacked;
            PrivateKeyExportable = privateKeyExportable;
            Created = created;
        }

        /// <summary>The public JWK to register with the server.</summary>
        public EcPublicJsonWebKey PublicKey { get; }

        /// <summary>Always <c>ES256</c>; the SDK generates nothing else.</summary>
        public string Algorithm => "ES256";

        /// <summary>Always <c>asn1_der</c>; see <see cref="IInstallationKeyStore.SignAsync"/>.</summary>
        public string SignatureFormat => "asn1_der";

        /// <summary>The store-specific alias or container name of the key.</summary>
        public string KeyAlias { get; }

        /// <summary>The provider that holds the key, for example <c>AndroidKeyStore</c>.</summary>
        public string Provider { get; }

        /// <summary>A provider-reported security level, for example <c>strongbox</c> or <c>software</c>.</summary>
        public string SecurityLevel { get; }

        /// <summary>Whether the provider claims the key lives in secure hardware.</summary>
        public bool HardwareBacked { get; }

        /// <summary>Whether the private key can be exported. A store that answers true is not device-binding anything.</summary>
        public bool PrivateKeyExportable { get; }

        /// <summary>
        /// Whether this call created the key. When a stored installation UUID
        /// outlives its key, the client must mint a new UUID rather than reuse
        /// the old one against a new public key, which the server would treat as
        /// a UUID collision.
        /// </summary>
        public bool Created { get; }
    }
}
