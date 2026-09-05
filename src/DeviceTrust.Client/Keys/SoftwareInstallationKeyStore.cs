using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// A P-256 key held in an ordinary file. <b>Protocol testing only.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This store exists so the protocol, the access proofs and the boundary
    /// tests can be exercised on a build machine, a Linux console or CI, where
    /// no keystore, Secure Enclave or TPM is available. It is the .NET
    /// equivalent of the software key the Python conformance suite uses, and it
    /// makes exactly the same claim: it proves the <i>wire protocol</i>, and it
    /// proves nothing at all about device binding.
    /// </para>
    /// <para>
    /// The private key is exportable by construction — it is a file — so
    /// <see cref="InstallationKeyMetadata.PrivateKeyExportable"/> reports
    /// <c>true</c> and <see cref="InstallationKeyMetadata.HardwareBacked"/>
    /// reports <c>false</c>. Copying that file to another machine transfers the
    /// installation identity with it, which is precisely the attack the real
    /// stores prevent. Never ship it in a production application; use
    /// <c>AndroidKeyStoreInstallationKeyStore</c>,
    /// <c>SecureEnclaveInstallationKeyStore</c> or
    /// <c>CngInstallationKeyStore</c> instead.
    /// </para>
    /// <para>
    /// The constructor requires an explicit acknowledgement argument so that no
    /// application can select this store by accident or by copying a sample.
    /// </para>
    /// </remarks>
    public sealed class SoftwareInstallationKeyStore : IInstallationKeyStore, IDisposable
    {
        private readonly string _keyFilePath;
        private readonly object _gate = new object();
        private ECDsa? _key;
        private bool _createdThisSession;

        /// <summary>
        /// Opens or creates a software key at <paramref name="keyFilePath"/>.
        /// </summary>
        /// <param name="keyFilePath">Where the PKCS#8 private key is stored.</param>
        /// <param name="acknowledgeNotHardwareBacked">
        /// Must be <c>true</c>. The argument exists to make the security
        /// trade-off a deliberate, greppable decision at every call site.
        /// </param>
        public SoftwareInstallationKeyStore(string keyFilePath, bool acknowledgeNotHardwareBacked)
        {
            if (string.IsNullOrWhiteSpace(keyFilePath))
            {
                throw new ArgumentException("A key file path is required.", nameof(keyFilePath));
            }

            if (!acknowledgeNotHardwareBacked)
            {
                throw new InstallationKeyException(
                    "SOFTWARE_KEY_NOT_ACKNOWLEDGED",
                    "SoftwareInstallationKeyStore provides no device binding and must be selected "
                    + "deliberately by passing acknowledgeNotHardwareBacked: true. Use a platform "
                    + "key store in any build that makes a security claim.");
            }

            _keyFilePath = keyFilePath;
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
                    if (File.Exists(_keyFilePath))
                    {
                        _key = LoadKey(_keyFilePath);
                    }
                    else
                    {
                        _key = CreateKey(_keyFilePath);
                        created = true;
                        _createdThisSession = true;
                    }
                }
                else
                {
                    created = _createdThisSession;
                }

                var parameters = _key.ExportParameters(false);
                var publicKey = new EcPublicJsonWebKey(
                    LeftPad(parameters.Q.X!, 32),
                    LeftPad(parameters.Q.Y!, 32));

                return Task.FromResult(new InstallationKeyMetadata(
                    publicKey,
                    keyAlias: Path.GetFileName(_keyFilePath),
                    provider: "software-file",
                    securityLevel: "software",
                    hardwareBacked: false,
                    privateKeyExportable: true,
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
                if (_key is null)
                {
                    if (!File.Exists(_keyFilePath))
                    {
                        throw new InstallationKeyException(
                            "KEY_NOT_FOUND",
                            "No software installation key exists yet. Call GetOrCreateKeyAsync first.");
                    }

                    _key = LoadKey(_keyFilePath);
                }

                return Task.FromResult(EcdsaSignatureFormat.SignDer(_key, data));
            }
        }

        /// <inheritdoc />
        public Task DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            lock (_gate)
            {
                _key?.Dispose();
                _key = null;
                _createdThisSession = false;
                if (File.Exists(_keyFilePath))
                {
                    File.Delete(_keyFilePath);
                }
            }

            return Task.CompletedTask;
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

        private static ECDsa CreateKey(string path)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory!);
            }

            File.WriteAllBytes(path, key.ExportPkcs8PrivateKey());
            RestrictToOwner(path);
            return key;
        }

        private static ECDsa LoadKey(string path)
        {
            var key = ECDsa.Create();
            try
            {
                key.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _);
            }
            catch (CryptographicException error)
            {
                key.Dispose();
                throw new InstallationKeyException(
                    "KEY_LOAD_FAILED",
                    "The stored software installation key could not be read.",
                    error);
            }

            return key;
        }

        private static void RestrictToOwner(string path)
        {
#if NET8_0_OR_GREATER
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
#else
            // .NET 6 has no managed chmod. The file inherits the process umask,
            // which is 0600-or-tighter under a normal user account. This store
            // is for protocol testing, so the gap is documented rather than
            // papered over with a P/Invoke that would then need per-OS handling.
            _ = path;
#endif
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
