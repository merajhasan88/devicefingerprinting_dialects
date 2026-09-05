using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Keys;

namespace DeviceTrust.Client.Windows.Keys
{
    /// <summary>
    /// An installation key held by Windows CNG, in the TPM where the machine has
    /// one and in the software key storage provider otherwise.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The key is created with <see cref="CngExportPolicies.None"/>, so CNG will
    /// not export the private key material through its own API, and the handle is
    /// all this process ever holds. When the Microsoft Platform Crypto Provider
    /// is available the key is generated inside the TPM and the private key never
    /// exists in system memory at all.
    /// </para>
    /// <para>
    /// <b>State this accurately.</b> A desktop CNG key is not equivalent to an
    /// AndroidKeyStore or Secure Enclave key. On a phone the OS keystore is the
    /// only path to the key and the application never runs as a privileged user;
    /// on Windows, an attacker with administrator rights on the machine can use
    /// the key as a signing oracle, and without a TPM the software KSP protects
    /// it with DPAPI rather than hardware. It is a real improvement over a key in
    /// a file, and it is not remote attestation. The property that survives in
    /// both cases is that a token stolen from this machine cannot be replayed
    /// from another one, because the signature cannot be produced there.
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public sealed class CngInstallationKeyStore : IInstallationKeyStore, IDisposable
    {
        private const string DefaultKeyName = "DeviceTrust.InstallationKey.v2";

        private readonly string _keyName;
        private readonly bool _machineScope;
        private readonly bool _preferTpm;
        private readonly object _gate = new object();

        private CngKey? _key;
        private bool _createdThisSession;
        private string _provider = "unknown";

        /// <summary>Creates a key store.</summary>
        /// <param name="keyName">The CNG key container name.</param>
        /// <param name="machineScope">
        /// Whether the key belongs to the machine rather than the current user. A
        /// per-user key is the right default for a desktop application: it dies
        /// with the profile and is not shared between accounts on the machine.
        /// </param>
        /// <param name="preferTpm">Whether to try the Platform Crypto Provider first.</param>
        public CngInstallationKeyStore(
            string? keyName = null,
            bool machineScope = false,
            bool preferTpm = true)
        {
            _keyName = string.IsNullOrWhiteSpace(keyName) ? DefaultKeyName : keyName!;
            _machineScope = machineScope;
            _preferTpm = preferTpm;
        }

        /// <inheritdoc />
        public Task<InstallationKeyMetadata> GetOrCreateKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                var created = false;
                if (_key is null)
                {
                    _key = OpenExisting();
                    if (_key is null)
                    {
                        _key = CreateKey();
                        created = true;
                        _createdThisSession = true;
                    }
                }
                else
                {
                    created = _createdThisSession;
                }

                using var ecdsa = new ECDsaCng(_key);
                var parameters = ecdsa.ExportParameters(false);
                var publicKey = new EcPublicJsonWebKey(
                    LeftPad(parameters.Q.X!, 32),
                    LeftPad(parameters.Q.Y!, 32));

                var hardwareBacked = string.Equals(
                    _provider,
                    CngProvider.MicrosoftPlatformCryptoProvider.Provider,
                    StringComparison.Ordinal);

                return Task.FromResult(new InstallationKeyMetadata(
                    publicKey,
                    keyAlias: _keyName,
                    provider: _provider,
                    securityLevel: hardwareBacked ? "tpm" : "software_ksp",
                    hardwareBacked: hardwareBacked,
                    privateKeyExportable: false,
                    created: created));
            }
        }

        /// <inheritdoc />
        public Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                _key ??= OpenExisting() ?? throw new InstallationKeyException(
                    "KEY_NOT_FOUND",
                    "The CNG installation key is missing. Call GetOrCreateKeyAsync to create a fresh identity.");

                try
                {
                    using var ecdsa = new ECDsaCng(_key);
                    // ECDsaCng.SignData's two-argument overload returns IEEE
                    // P-1363. Routing through the shared helper is what keeps the
                    // DER requirement in one place instead of in every store.
                    return Task.FromResult(EcdsaSignatureFormat.SignDer(ecdsa, data));
                }
                catch (CryptographicException error)
                {
                    throw new InstallationKeyException(
                        "SIGNING_FAILED",
                        "CNG could not sign with the installation key.",
                        error);
                }
            }
        }

        /// <inheritdoc />
        public Task DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                var key = _key ?? OpenExisting();
                _key = null;
                _createdThisSession = false;
                if (key is null)
                {
                    return Task.CompletedTask;
                }

                try
                {
                    key.Delete();
                }
                catch (CryptographicException error)
                {
                    throw new InstallationKeyException(
                        "KEY_DELETE_FAILED",
                        "CNG could not delete the installation key.",
                        error);
                }
                finally
                {
                    key.Dispose();
                }

                return Task.CompletedTask;
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            lock (_gate)
            {
                _key?.Dispose();
                _key = null;
            }
        }

        private CngKey? OpenExisting()
        {
            foreach (var provider in CandidateProviders())
            {
                try
                {
                    if (!CngKey.Exists(_keyName, provider, OpenOptions()))
                    {
                        continue;
                    }

                    var key = CngKey.Open(_keyName, provider, OpenOptions());
                    if (!IsExpectedP256Key(key))
                    {
                        // An interrupted earlier run may have left something else
                        // under this name. Replace it, and report created=true so
                        // the caller rotates the installation UUID rather than
                        // presenting the old one with a new public key.
                        key.Delete();
                        key.Dispose();
                        continue;
                    }

                    _provider = provider.Provider;
                    return key;
                }
                catch (CryptographicException)
                {
                    // A provider that is present but refuses this key is not an
                    // error; the next candidate, or creation, is the answer.
                }
            }

            return null;
        }

        private CngKey CreateKey()
        {
            CryptographicException? lastError = null;
            foreach (var provider in CandidateProviders())
            {
                var parameters = new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyCreationOptions = _machineScope
                        ? CngKeyCreationOptions.MachineKey
                        : CngKeyCreationOptions.None,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                };

                try
                {
                    var key = CngKey.Create(CngAlgorithm.ECDsaP256, _keyName, parameters);
                    _provider = provider.Provider;
                    return key;
                }
                catch (CryptographicException error)
                {
                    // A machine may advertise a TPM that cannot satisfy this
                    // algorithm. Fall through to the software provider rather than
                    // failing the whole enrolment, exactly as the Android store
                    // falls back from StrongBox.
                    lastError = error;
                }
                catch (PlatformNotSupportedException error)
                {
                    throw new InstallationKeyException(
                        "KEYSTORE_UNAVAILABLE",
                        "Windows CNG is not available in this process.",
                        error);
                }
            }

            throw new InstallationKeyException(
                "KEY_GENERATION_FAILED",
                "No CNG provider could create the P-256 installation key.",
                lastError);
        }

        private CngProvider[] CandidateProviders()
        {
            return _preferTpm
                ? new[]
                {
                    CngProvider.MicrosoftPlatformCryptoProvider,
                    CngProvider.MicrosoftSoftwareKeyStorageProvider,
                }
                : new[] { CngProvider.MicrosoftSoftwareKeyStorageProvider };
        }

        private CngKeyOpenOptions OpenOptions()
        {
            return _machineScope ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        }

        private static bool IsExpectedP256Key(CngKey key)
        {
            return key.Algorithm == CngAlgorithm.ECDsaP256
                   || string.Equals(key.Algorithm.Algorithm, "ECDSA_P256", StringComparison.Ordinal);
        }

        private static byte[] LeftPad(byte[] value, int size)
        {
            if (value.Length == size)
            {
                return value;
            }

            if (value.Length > size)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The EC coordinate is larger than P-256 permits.");
            }

            var padded = new byte[size];
            Buffer.BlockCopy(value, 0, padded, size - value.Length, value.Length);
            return padded;
        }
    }
}
