using System;
using System.Threading;
using System.Threading.Tasks;
using Android.Content;
using Android.OS;
using Android.Security.Keystore;
using DeviceTrust.Client.Keys;
using Java.Security;
using Java.Security.Interfaces;
using Java.Security.Spec;

namespace DeviceTrust.Client.Maui.Android
{
    /// <summary>
    /// One non-exportable P-256 signing key in AndroidKeyStore, StrongBox-backed
    /// where the device supports it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the direct .NET port of the Kotlin <c>InstallationKeyManager</c>
    /// the Flutter client uses, and it keeps the same property: the private key
    /// object here is only a handle. Android performs the signing inside the
    /// keystore, and the only things that cross back into managed code are the
    /// public EC coordinates and DER signatures.
    /// </para>
    /// <para>
    /// StrongBox is attempted and then abandoned quietly on failure, because some
    /// devices advertise <c>FEATURE_STRONGBOX_KEYSTORE</c> yet cannot satisfy a
    /// particular algorithm and digest combination. Failing enrolment on those
    /// devices would be worse than falling back to the TEE, and
    /// <see cref="InstallationKeyMetadata.SecurityLevel"/> reports honestly which
    /// one ended up holding the key.
    /// </para>
    /// </remarks>
    public sealed class AndroidKeyStoreInstallationKeyStore : IInstallationKeyStore
    {
        private const string AndroidKeyStoreName = "AndroidKeyStore";
        private const string CurveName = "secp256r1";

        private readonly Context _context;
        private readonly string _keyAlias;
        private readonly object _gate = new object();

        private bool _createdThisSession;

        /// <summary>Creates a key store bound to the application's package name.</summary>
        public AndroidKeyStoreInstallationKeyStore(Context context, string? keyAlias = null)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _keyAlias = keyAlias
                        ?? _context.PackageName + ".device_recognition.installation_key.v2";
        }

        /// <inheritdoc />
        public Task<InstallationKeyMetadata> GetOrCreateKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireSupportedAndroid();

            lock (_gate)
            {
                var keyStore = LoadKeyStore();
                var created = false;

                if (!keyStore.ContainsAlias(_keyAlias))
                {
                    GenerateKeyPair(keyStore);
                    created = true;
                }

                var entry = PrivateKeyEntry(keyStore);
                if (!IsExpectedP256Key(entry))
                {
                    // An interrupted development build can leave a different key
                    // under this alias. Replace it and report created=true so the
                    // caller rotates the installation UUID: presenting the old
                    // UUID with a new public key is the collision the server
                    // refuses.
                    keyStore.DeleteEntry(_keyAlias);
                    GenerateKeyPair(keyStore);
                    created = true;
                    entry = PrivateKeyEntry(keyStore);
                }

                _createdThisSession |= created;

                if (entry.Certificate?.PublicKey is not IECPublicKey publicKey)
                {
                    throw new InstallationKeyException(
                        "INVALID_PUBLIC_KEY",
                        "AndroidKeyStore did not return an EC public key.");
                }

                var point = publicKey.GetW()
                            ?? throw new InstallationKeyException(
                                "INVALID_PUBLIC_KEY",
                                "AndroidKeyStore returned an EC key with no public point.");
                var jwk = new EcPublicJsonWebKey(
                    UnsignedFixed(point.AffineX!, 32),
                    UnsignedFixed(point.AffineY!, 32));

                var (level, hardwareBacked) = DescribeSecurity(entry);

                return Task.FromResult(new InstallationKeyMetadata(
                    jwk,
                    keyAlias: _keyAlias,
                    provider: AndroidKeyStoreName,
                    securityLevel: level,
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
            RequireSupportedAndroid();

            lock (_gate)
            {
                var keyStore = LoadKeyStore();
                if (!keyStore.ContainsAlias(_keyAlias))
                {
                    throw new InstallationKeyException(
                        "KEY_NOT_FOUND",
                        "The Android installation key is missing. Restart the app to create a fresh installation identity.");
                }

                var entry = PrivateKeyEntry(keyStore);
                try
                {
                    var signer = Signature.GetInstance("SHA256withECDSA")
                                 ?? throw new InstallationKeyException(
                                     "SIGNING_FAILED",
                                     "SHA256withECDSA is unavailable on this device.");
                    signer.InitSign(entry.PrivateKey);
                    signer.Update(data);

                    // JCA's SHA256withECDSA output is ASN.1 DER, which is exactly
                    // what the server verifies. No re-encoding is needed here, and
                    // none must be added.
                    var signature = signer.Sign()
                                    ?? throw new InstallationKeyException(
                                        "SIGNING_FAILED",
                                        "AndroidKeyStore returned no signature.");
                    return Task.FromResult(signature);
                }
                catch (GeneralSecurityException error)
                {
                    throw new InstallationKeyException(
                        "SIGNING_FAILED",
                        "AndroidKeyStore could not sign with the installation key.",
                        error);
                }
            }
        }

        /// <inheritdoc />
        public Task DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireSupportedAndroid();

            lock (_gate)
            {
                var keyStore = LoadKeyStore();
                try
                {
                    if (keyStore.ContainsAlias(_keyAlias))
                    {
                        keyStore.DeleteEntry(_keyAlias);
                    }

                    _createdThisSession = false;
                    return Task.CompletedTask;
                }
                catch (GeneralSecurityException error)
                {
                    throw new InstallationKeyException(
                        "KEY_DELETE_FAILED",
                        "AndroidKeyStore could not delete the installation key.",
                        error);
                }
            }
        }

        private static void RequireSupportedAndroid()
        {
            if (Build.VERSION.SdkInt < BuildVersionCodes.M)
            {
                throw new InstallationKeyException(
                    "UNSUPPORTED_ANDROID_VERSION",
                    "A non-exportable keystore key requires Android 6.0 (API 23) or newer.");
            }
        }

        private static KeyStore LoadKeyStore()
        {
            try
            {
                var keyStore = KeyStore.GetInstance(AndroidKeyStoreName)
                               ?? throw new InstallationKeyException(
                                   "KEYSTORE_UNAVAILABLE",
                                   "AndroidKeyStore is unavailable.");
                keyStore.Load(null);
                return keyStore;
            }
            catch (GeneralSecurityException error)
            {
                throw new InstallationKeyException(
                    "KEYSTORE_UNAVAILABLE",
                    "AndroidKeyStore is unavailable.",
                    error);
            }
        }

        private void GenerateKeyPair(KeyStore keyStore)
        {
            // OperatingSystem.IsAndroidVersionAtLeast is what the platform-compatibility
            // analyzer understands; a Build.VERSION.SdkInt comparison guards the call
            // correctly at run time but leaves CA1416 unsatisfied at compile time.
            var canTryStrongBox = OperatingSystem.IsAndroidVersionAtLeast(28)
                                  && _context.PackageManager?.HasSystemFeature(
                                      global::Android.Content.PM.PackageManager.FeatureStrongboxKeystore) == true;

            if (canTryStrongBox)
            {
                try
                {
                    GenerateKeyPair(preferStrongBox: true);
                    return;
                }
                catch (Exception)
                {
                    try
                    {
                        if (keyStore.ContainsAlias(_keyAlias))
                        {
                            keyStore.DeleteEntry(_keyAlias);
                        }
                    }
                    catch (GeneralSecurityException)
                    {
                        // The regular attempt below produces the actionable error
                        // if the keystore is genuinely unusable.
                    }
                }
            }

            GenerateKeyPair(preferStrongBox: false);
        }

        private void GenerateKeyPair(bool preferStrongBox)
        {
            try
            {
                var generator = KeyPairGenerator.GetInstance(
                                    KeyProperties.KeyAlgorithmEc,
                                    AndroidKeyStoreName)
                                ?? throw new InstallationKeyException(
                                    "KEY_GENERATION_FAILED",
                                    "The EC key pair generator is unavailable.");

                var builder = new KeyGenParameterSpec.Builder(_keyAlias, KeyStorePurpose.Sign)
                    .SetAlgorithmParameterSpec(new ECGenParameterSpec(CurveName))!
                    .SetDigests(KeyProperties.DigestSha256)!
                    .SetUserAuthenticationRequired(false)!;

                if (preferStrongBox && OperatingSystem.IsAndroidVersionAtLeast(28))
                {
                    builder = builder.SetIsStrongBoxBacked(true)!;
                }

                generator.Initialize(builder.Build());
                generator.GenerateKeyPair();
            }
            catch (GeneralSecurityException error)
            {
                throw new InstallationKeyException(
                    "KEY_GENERATION_FAILED",
                    preferStrongBox
                        ? "StrongBox could not create the P-256 installation key."
                        : "AndroidKeyStore could not create the P-256 installation key.",
                    error);
            }
            catch (ProviderException error)
            {
                throw new InstallationKeyException(
                    "KEY_GENERATION_FAILED",
                    preferStrongBox
                        ? "StrongBox could not create the P-256 installation key."
                        : "AndroidKeyStore could not create the P-256 installation key.",
                    error);
            }
        }

        private KeyStore.PrivateKeyEntry PrivateKeyEntry(KeyStore keyStore)
        {
            try
            {
                return keyStore.GetEntry(_keyAlias, null) as KeyStore.PrivateKeyEntry
                       ?? throw new InstallationKeyException(
                           "KEY_NOT_FOUND",
                           "The Android installation key entry is missing or has the wrong type.");
            }
            catch (GeneralSecurityException error)
            {
                throw new InstallationKeyException(
                    "KEY_LOOKUP_FAILED",
                    "AndroidKeyStore could not load the installation key.",
                    error);
            }
        }

        private static bool IsExpectedP256Key(KeyStore.PrivateKeyEntry entry)
        {
            return entry.Certificate?.PublicKey is IECPublicKey publicKey
                   && publicKey.Params?.Curve?.Field?.FieldSize == 256;
        }

        private (string Level, bool HardwareBacked) DescribeSecurity(KeyStore.PrivateKeyEntry entry)
        {
            try
            {
                var factory = KeyFactory.GetInstance(entry.PrivateKey!.Algorithm!, AndroidKeyStoreName);
                var info = factory!.GetKeySpec(
                    entry.PrivateKey,
                    Java.Lang.Class.FromType(typeof(KeyInfo))) as KeyInfo;
                if (info is null)
                {
                    return ("unknown", false);
                }

                if (OperatingSystem.IsAndroidVersionAtLeast(31))
                {
                    // KeyInfo.SecurityLevel is an int; KeyStoreSecurityLevel is the
                    // enum that names its values.
                    return (KeyStoreSecurityLevel)info.SecurityLevel switch
                    {
                        KeyStoreSecurityLevel.Strongbox => ("strongbox", true),
                        KeyStoreSecurityLevel.TrustedEnvironment => ("trusted_execution_environment", true),
                        // UNKNOWN_SECURE means the keystore is confident the key is
                        // in secure hardware but cannot say which kind. Reporting it
                        // as hardware-backed is accurate; reporting it as unknown
                        // would understate a real TEE key.
                        KeyStoreSecurityLevel.UnknownSecure => ("secure_hardware", true),
                        KeyStoreSecurityLevel.Software => ("software", false),
                        _ => ("unknown", false),
                    };
                }

#pragma warning disable CA1422 // IsInsideSecureHardware is the only answer before API 31.
                return info.IsInsideSecureHardware ? ("secure_hardware", true) : ("software", false);
#pragma warning restore CA1422
            }
            catch (Exception)
            {
                // The security level is descriptive metadata, never a gate. An
                // unreadable level must not stop the key from being used.
                return ("unknown", false);
            }
        }

        private static byte[] UnsignedFixed(Java.Math.BigInteger value, int size)
        {
            var raw = value.ToByteArray() ?? Array.Empty<byte>();
            var offset = 0;
            if (raw.Length == size + 1 && raw[0] == 0)
            {
                offset = 1;
            }

            var length = raw.Length - offset;
            if (length > size)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The EC coordinate is larger than P-256 permits.");
            }

            var output = new byte[size];
            Buffer.BlockCopy(raw, offset, output, size - length, length);
            return output;
        }
    }
}
