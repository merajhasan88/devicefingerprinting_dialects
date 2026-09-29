using System;

namespace DeviceTrust.Client.Keys
{
    /// <summary>What a step-up key store reports about the key it holds.</summary>
    public sealed class StepUpKeyMetadata
    {
        /// <summary>Creates step-up key metadata.</summary>
        public StepUpKeyMetadata(
            EcPublicJsonWebKey publicKey,
            StepUpKeyAuth auth,
            string provider,
            string securityLevel,
            bool hardwareBacked,
            bool created)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Auth = auth ?? throw new ArgumentNullException(nameof(auth));
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
            SecurityLevel = securityLevel ?? throw new ArgumentNullException(nameof(securityLevel));
            HardwareBacked = hardwareBacked;
            Created = created;
        }

        /// <summary>The public JWK sent as <c>stepup_public_key</c>.</summary>
        public EcPublicJsonWebKey PublicKey { get; }

        /// <summary>What the keystore enforces for this key, read back after creation.</summary>
        public StepUpKeyAuth Auth { get; }

        /// <summary>The provider holding the key, for example <c>AndroidKeyStore</c>.</summary>
        public string Provider { get; }

        /// <summary>The provider-reported security level.</summary>
        public string SecurityLevel { get; }

        /// <summary>Whether the provider claims the key lives in secure hardware.</summary>
        public bool HardwareBacked { get; }

        /// <summary>Whether this call created the key.</summary>
        public bool Created { get; }

        /// <summary>The RFC 7638 thumbprint the re-enrolment proof names.</summary>
        public string Thumbprint => PublicKey.Thumbprint;
    }
}
