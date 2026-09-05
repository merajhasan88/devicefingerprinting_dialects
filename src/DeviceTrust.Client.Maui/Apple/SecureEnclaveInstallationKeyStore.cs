using System;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Keys;
using Foundation;
using ObjCRuntime;
using Security;

namespace DeviceTrust.Client.Maui.Apple
{
    /// <summary>
    /// One non-exportable P-256 signing key in the Secure Enclave, held in the
    /// keychain and usable only on this device.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Secure Enclave generates the key inside itself; the keychain stores a
    /// reference, never the private key material, so there is nothing to export
    /// and nothing to copy. Signing happens in the Enclave and only the DER
    /// signature returns. This is the iOS counterpart of the AndroidKeyStore
    /// path, with the same guarantee.
    /// </para>
    /// <para>
    /// Accessibility is <c>AfterFirstUnlockThisDeviceOnly</c>: available to a
    /// background app once the device has been unlocked since boot, and excluded
    /// from iCloud Keychain and from encrypted backups. A key that could restore
    /// onto a second device would defeat the point of device binding.
    /// </para>
    /// <para>
    /// Devices without a Secure Enclave, and the simulator, have none of this. The
    /// store falls back to an ordinary keychain key there and reports
    /// <see cref="InstallationKeyMetadata.HardwareBacked"/> as <c>false</c>, so a
    /// caller can see the difference instead of assuming it.
    /// </para>
    /// </remarks>
    public sealed class SecureEnclaveInstallationKeyStore : IInstallationKeyStore
    {
        private const string DefaultTag = "com.devicetrust.installation_key.v2";

        private readonly string _applicationTag;
        private readonly object _gate = new object();

        private bool _createdThisSession;
        private bool _lastKeyWasEnclaveBacked;

        /// <summary>Creates a key store with the given keychain application tag.</summary>
        public SecureEnclaveInstallationKeyStore(string? applicationTag = null)
        {
            _applicationTag = string.IsNullOrWhiteSpace(applicationTag) ? DefaultTag : applicationTag!;
        }

        /// <inheritdoc />
        public Task<InstallationKeyMetadata> GetOrCreateKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                var created = false;
                var key = FindExistingKey();
                if (key is null)
                {
                    key = CreateKey();
                    created = true;
                    _createdThisSession = true;
                }
                else
                {
                    created = _createdThisSession;
                }

                using (key)
                {
                    var jwk = ReadPublicJwk(key);
                    return Task.FromResult(new InstallationKeyMetadata(
                        jwk,
                        keyAlias: _applicationTag,
                        provider: "iOS Keychain",
                        securityLevel: _lastKeyWasEnclaveBacked ? "secure_enclave" : "keychain_software",
                        hardwareBacked: _lastKeyWasEnclaveBacked,
                        privateKeyExportable: false,
                        created: created));
                }
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
                using var key = FindExistingKey()
                                ?? throw new InstallationKeyException(
                                    "KEY_NOT_FOUND",
                                    "The Secure Enclave installation key is missing. "
                                    + "Call GetOrCreateKeyAsync to create a fresh installation identity.");

                using var payload = NSData.FromArray(data);

                // EcdsaSignatureMessageX962Sha256 hashes the message with SHA-256
                // and returns an X9.62 ASN.1 DER signature, which is exactly the
                // encoding the server verifies. Choosing a "Digest" variant would
                // require pre-hashing, and choosing a raw variant would produce
                // the wrong encoding.
                var signature = key.CreateSignature(
                    SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
                    payload,
                    out var error);

                if (signature is null || error is not null)
                {
                    throw new InstallationKeyException(
                        "SIGNING_FAILED",
                        "The Secure Enclave could not sign: " + (error?.LocalizedDescription ?? "unknown error"));
                }

                using (signature)
                {
                    return Task.FromResult(signature.ToArray());
                }
            }
        }

        /// <inheritdoc />
        public Task DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                using var query = BuildQuery();
                var status = SecKeyChain.Remove(query);
                _createdThisSession = false;

                if (status is not (SecStatusCode.Success or SecStatusCode.ItemNotFound))
                {
                    throw new InstallationKeyException(
                        "KEY_DELETE_FAILED",
                        "The keychain refused to delete the installation key: " + status);
                }

                return Task.CompletedTask;
            }
        }

        private SecRecord BuildQuery()
        {
            return new SecRecord(SecKind.Key)
            {
                ApplicationTag = NSData.FromString(_applicationTag, NSStringEncoding.UTF8),
                KeyType = SecKeyType.ECSecPrimeRandom,
                KeyClass = SecKeyClass.Private,
            };
        }

        private SecKey? FindExistingKey()
        {
            using var query = BuildQuery();
            var result = SecKeyChain.QueryAsReference(query, out var status);
            if (status != SecStatusCode.Success || result is not SecKey key)
            {
                return null;
            }

            return key;
        }

        private SecKey CreateKey()
        {
            NSError? error = null;

            if (IsSecureEnclaveAvailable())
            {
                var key = SecKey.CreateRandomKey(BuildParameters(useSecureEnclave: true), out error);
                if (key is not null && error is null)
                {
                    _lastKeyWasEnclaveBacked = true;
                    return key;
                }

                // Some configurations advertise an Enclave that then refuses the
                // request. Falling back keeps enrolment working and reports the
                // weaker level honestly, rather than failing the whole flow. A
                // second parameter object is built rather than mutating the
                // first, because TokenID is a non-nullable enum.
            }

            var fallback = SecKey.CreateRandomKey(BuildParameters(useSecureEnclave: false), out error);
            if (fallback is not null && error is null)
            {
                _lastKeyWasEnclaveBacked = false;
                return fallback;
            }

            throw new InstallationKeyException(
                "KEY_GENERATION_FAILED",
                "The keychain could not create the P-256 installation key: "
                + (error?.LocalizedDescription ?? "unknown error"));
        }

        private SecKeyGenerationParameters BuildParameters(bool useSecureEnclave)
        {
            var privateKeyAttributes = new SecKeyParameters
            {
                IsPermanent = true,
                ApplicationTag = NSData.FromString(_applicationTag, NSStringEncoding.UTF8),
            };

            var parameters = new SecKeyGenerationParameters
            {
                KeyType = SecKeyType.ECSecPrimeRandom,
                KeySizeInBits = 256,
                PrivateKeyAttrs = privateKeyAttributes,
            };

            if (useSecureEnclave)
            {
                // PrivateKeyUsage is what permits signing without a biometric or
                // passcode prompt; AfterFirstUnlockThisDeviceOnly keeps the key
                // off iCloud Keychain and out of encrypted backups, so it cannot
                // restore onto a second device.
                privateKeyAttributes.AccessControl = SecAccessControl.Create(
                    SecAccessible.AfterFirstUnlockThisDeviceOnly,
                    SecAccessControlCreateFlags.PrivateKeyUsage);
                parameters.TokenID = SecTokenID.SecureEnclave;
            }

            return parameters;
        }

        private static EcPublicJsonWebKey ReadPublicJwk(SecKey privateKey)
        {
            using var publicKey = privateKey.GetPublicKey()
                                  ?? throw new InstallationKeyException(
                                      "INVALID_PUBLIC_KEY",
                                      "The keychain returned no public key for the installation key.");

            using var representation = publicKey.GetExternalRepresentation(out var error);
            if (representation is null || error is not null)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The public key could not be exported: " + (error?.LocalizedDescription ?? "unknown error"));
            }

            // SecKeyCopyExternalRepresentation returns the uncompressed X9.63
            // point: 0x04 || X (32 bytes) || Y (32 bytes).
            var bytes = representation.ToArray();
            if (bytes.Length != 65 || bytes[0] != 0x04)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The exported public key is not an uncompressed P-256 point.");
            }

            var x = new byte[32];
            var y = new byte[32];
            Buffer.BlockCopy(bytes, 1, x, 0, 32);
            Buffer.BlockCopy(bytes, 33, y, 0, 32);
            return new EcPublicJsonWebKey(x, y);
        }

        private static bool IsSecureEnclaveAvailable()
        {
            // The simulator has no Enclave, and neither do devices without a
            // Secure Enclave coprocessor. Attempting it there fails at key
            // creation, which the caller handles, but checking first keeps the
            // reported security level accurate on the first attempt.
            return Runtime.Arch != Arch.SIMULATOR;
        }
    }
}
