using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Hardware.Biometrics;
using Android.OS;
using Android.Runtime;
using Android.Security.Keystore;
using DeviceTrust.Client.Keys;
using Java.Security;
using Java.Security.Interfaces;
using Java.Security.Spec;

namespace DeviceTrust.Client.Maui.Android
{
    /// <summary>
    /// The optional step-up key in AndroidKeyStore: a second non-exportable P-256
    /// key that cannot sign without a device authentication (DESIGN.md 51 and 53).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A port of the Flutter client's <c>StepUpKeyManager.kt</c>, kept to the
    /// owner's "Option 1" of DESIGN.md 53:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// Android 11+ (API 30): per-use. Each signature is authorised by its own
    /// <see cref="BiometricPrompt"/> with a <c>CryptoObject</c>, device credential
    /// (passcode) by default.
    /// </description></item>
    /// <item><description>
    /// Android 9/10 with the passcode factor: Keystore cannot bind a device
    /// credential to one operation before API 30, so the key gets a 30-second
    /// hardware-enforced window. The confirm-credential screen is still shown
    /// before every signature, but that prompt is enforced by the app; the
    /// hardware guarantees only "authenticated in the last 30 s", and the key is
    /// reported as <c>windowed</c> so the server records the downgrade.
    /// </description></item>
    /// </list>
    /// <para>
    /// Factor, mode and window are read back from <see cref="KeyInfo"/> — what
    /// the keystore enforces — never echoed from the request.
    /// </para>
    /// <para>
    /// Dead keys (DESIGN.md 57): after the screen lock is removed, Android 9
    /// keeps the alias but <c>getEntry</c> throws <c>UnrecoverableKeyException</c>;
    /// newer keystores keep the entry and throw
    /// <c>KeyPermanentlyInvalidatedException</c> at <c>initSign</c>. Both, and an
    /// alias holding no private key, are treated as dead: the key is deleted and
    /// <see cref="StepUpErrorCodes.KeyInvalidated"/> reported, saying truthfully
    /// whether removal worked — on the OPPO it did not while the lock was off.
    /// </para>
    /// <para>
    /// Signing needs an <see cref="Activity"/> to show the prompt. On API &lt; 30
    /// the confirm-credential result arrives in the host activity's
    /// <c>OnActivityResult</c>, which must forward it to
    /// <see cref="OnActivityResult"/>.
    /// </para>
    /// </remarks>
    public sealed class AndroidStepUpKeyStore : IStepUpKeyStore
    {
        /// <summary>The request code of the API &lt; 30 confirm-credential screen.</summary>
        public const int ConfirmCredentialRequestCode = 0x5354; // "ST"

        private const string AndroidKeyStoreName = "AndroidKeyStore";
        private const string CurveName = "secp256r1";
        private const int MaxPayloadBytes = 65536;

        private readonly Context _context;
        private readonly Func<Activity?> _activity;
        private readonly string _keyAlias;
        private readonly object _gate = new object();

        private string _requestedMode = StepUpKeyAuth.ModePerUse;
        private PendingConfirm? _pendingConfirm;
        private bool _signing;

        /// <summary>Creates the store.</summary>
        /// <param name="context">The application context.</param>
        /// <param name="activity">Returns the foreground activity to show prompts on.</param>
        /// <param name="keyAlias">Overrides the alias; defaults to the Flutter client's naming.</param>
        public AndroidStepUpKeyStore(Context context, Func<Activity?> activity, string? keyAlias = null)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _activity = activity ?? throw new ArgumentNullException(nameof(activity));
            _keyAlias = keyAlias ?? _context.PackageName + ".device_recognition.stepup_key.v1";
        }

        /// <inheritdoc />
        public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(
            StepUpKeyAuth requested,
            CancellationToken cancellationToken = default)
        {
            if (requested is null)
            {
                throw new ArgumentNullException(nameof(requested));
            }

            cancellationToken.ThrowIfCancellationRequested();
            RequireSupportedAndroid();

            lock (_gate)
            {
                _requestedMode = requested.Mode;

                // An existing key is checked before the screen lock: removing the
                // lock is what kills it, so this is where it can be said precisely.
                var keyStore = LoadKeyStore();
                if (keyStore.ContainsAlias(_keyAlias))
                {
                    LiveEntry(keyStore);
                }

                RequireDeviceCredential();
                if (requested.Factor == StepUpKeyAuth.FactorBiometric && !OperatingSystem.IsAndroidVersionAtLeast(28))
                {
                    throw new InstallationKeyException(
                        StepUpErrorCodes.Unsupported,
                        "Biometric step-up needs Android 9 (API 28) or newer.");
                }

                var created = false;
                if (!keyStore.ContainsAlias(_keyAlias))
                {
                    GenerateKeyPair(keyStore, requested);
                    created = true;
                }

                var entry = LiveEntry(keyStore);
                var publicKey = entry.Certificate?.PublicKey?.JavaCast<IECPublicKey>()
                                ?? throw new InstallationKeyException(
                                    "INVALID_PUBLIC_KEY",
                                    "AndroidKeyStore did not return an EC public key for the step-up key.");
                var point = publicKey.GetW()
                            ?? throw new InstallationKeyException(
                                "INVALID_PUBLIC_KEY",
                                "AndroidKeyStore returned a step-up key with no public point.");

                var info = KeyInfoOf(entry);
                var (level, hardwareBacked) = DescribeSecurity(info);
                return Task.FromResult(new StepUpKeyMetadata(
                    new EcPublicJsonWebKey(UnsignedFixed(point.AffineX!, 32), UnsignedFixed(point.AffineY!, 32)),
                    DescribeAuth(info),
                    AndroidKeyStoreName,
                    level,
                    hardwareBacked,
                    created));
            }
        }

        /// <inheritdoc />
        public Task<byte[]> SignAsync(byte[] data, string reason, CancellationToken cancellationToken = default)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            cancellationToken.ThrowIfCancellationRequested();
            RequireSupportedAndroid();
            if (data.Length > MaxPayloadBytes)
            {
                throw new InstallationKeyException(
                    "PAYLOAD_TOO_LARGE",
                    "The step-up payload is larger than " + MaxPayloadBytes + " bytes.");
            }

            var activity = _activity()
                           ?? throw new InstallationKeyException(
                               StepUpErrorCodes.SigningFailed,
                               "No foreground activity is available to show the step-up prompt.");

            var completion = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate)
            {
                if (_signing)
                {
                    throw new InstallationKeyException(
                        StepUpErrorCodes.Busy,
                        "A step-up authentication is already in progress.");
                }

                _signing = true;
            }

            void Done(byte[]? signature, Exception? error)
            {
                lock (_gate)
                {
                    _signing = false;
                }

                if (error is not null)
                {
                    completion.TrySetException(error);
                }
                else
                {
                    completion.TrySetResult(signature!);
                }
            }

            activity.RunOnUiThread(() => BeginSign(activity, data, reason ?? string.Empty, Done));
            return completion.Task;
        }

        /// <summary>
        /// Delivers the API &lt; 30 confirm-credential result. Returns true when
        /// the request was this store's.
        /// </summary>
        public bool OnActivityResult(int requestCode, Result resultCode)
        {
            if (requestCode != ConfirmCredentialRequestCode)
            {
                return false;
            }

            PendingConfirm? pending;
            lock (_gate)
            {
                pending = _pendingConfirm;
                _pendingConfirm = null;
            }

            if (pending is null)
            {
                return true;
            }

            if (resultCode == Result.Ok)
            {
                SignAndReport(pending.Entry, pending.Payload, pending.Done);
            }
            else
            {
                pending.Done(null, new InstallationKeyException(
                    StepUpErrorCodes.Cancelled,
                    "The passcode prompt was cancelled."));
            }

            return true;
        }

        /// <inheritdoc />
        public Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireSupportedAndroid();
            lock (_gate)
            {
                var keyStore = LoadKeyStore();
                try
                {
                    if (!keyStore.ContainsAlias(_keyAlias))
                    {
                        return Task.FromResult(false);
                    }

                    keyStore.DeleteEntry(_keyAlias);
                    return Task.FromResult(true);
                }
                catch (GeneralSecurityException error)
                {
                    throw new InstallationKeyException(
                        "KEY_DELETE_FAILED",
                        "AndroidKeyStore could not delete the step-up key.",
                        error);
                }
            }
        }

        // ------------------------------------------------------------ signing

        private void BeginSign(Activity activity, byte[] payload, string reason, Action<byte[]?, Exception?> done)
        {
            try
            {
                KeyStore.PrivateKeyEntry entry;
                StepUpKeyAuth auth;
                lock (_gate)
                {
                    var keyStore = LoadKeyStore();
                    if (!keyStore.ContainsAlias(_keyAlias))
                    {
                        throw new InstallationKeyException(
                            StepUpErrorCodes.KeyNotFound,
                            "No step-up key exists on this installation.");
                    }

                    entry = LiveEntry(keyStore);
                    auth = DescribeAuth(KeyInfoOf(entry));
                }

                if (auth.Mode == StepUpKeyAuth.ModePerUse)
                {
                    if (!OperatingSystem.IsAndroidVersionAtLeast(28))
                    {
                        throw new InstallationKeyException(
                            StepUpErrorCodes.Unsupported,
                            "A per-use step-up key needs Android 9 (API 28) or newer to prompt.");
                    }

                    var signer = Signature.GetInstance("SHA256withECDSA")!;
                    signer.InitSign(entry.PrivateKey);
                    AuthenticateOperation(activity, signer, auth.Factor, reason, payload, done);
                    return;
                }

                if (_requestedMode == StepUpKeyAuth.ModeWindowed)
                {
                    // A key the app asked to be windowed signs without a prompt
                    // while its hardware window is open.
                    try
                    {
                        done(SignNow(entry, payload), null);
                        return;
                    }
                    catch (UserNotAuthenticatedException)
                    {
                        // The window is closed; authenticate below and sign.
                    }
                }

                AuthenticateThenSign(activity, entry, auth.Factor, reason, payload, done);
            }
            catch (KeyPermanentlyInvalidatedException error)
            {
                done(null, DiscardDeadKey(error));
            }
            catch (InstallationKeyException error)
            {
                done(null, error);
            }
            catch (GeneralSecurityException error)
            {
                done(null, new InstallationKeyException(
                    StepUpErrorCodes.SigningFailed,
                    "AndroidKeyStore could not prepare the step-up signature: " + error.Message,
                    error));
            }
        }

        /// <summary>Per-use: the prompt authorises this one Signature object.</summary>
        [SupportedOSPlatform("android28.0")]
        private static void AuthenticateOperation(
            Activity activity,
            Signature signer,
            string factor,
            string reason,
            byte[] payload,
            Action<byte[]?, Exception?> done)
        {
            var prompt = BuildPrompt(activity, factor, reason, done);
            prompt.Authenticate(
                new BiometricPrompt.CryptoObject(signer),
                new CancellationSignal(),
                activity.MainExecutor!,
                new PromptCallback(
                    result =>
                    {
                        var authorised = result?.CryptoObject?.Signature ?? signer;
                        try
                        {
                            authorised.Update(payload);
                            done(authorised.Sign(), null);
                        }
                        catch (GeneralSecurityException error)
                        {
                            done(null, SigningFailed(error));
                        }
                    },
                    error => done(null, error)));
        }

        /// <summary>Windowed: authenticate first, then sign inside the hardware window.</summary>
        private void AuthenticateThenSign(
            Activity activity,
            KeyStore.PrivateKeyEntry entry,
            string factor,
            string reason,
            byte[] payload,
            Action<byte[]?, Exception?> done)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                var prompt = BuildPrompt(activity, factor, reason, done);
                prompt.Authenticate(
                    new CancellationSignal(),
                    activity.MainExecutor!,
                    new PromptCallback(_ => SignAndReport(entry, payload, done), error => done(null, error)));
                return;
            }

            // API < 30: the system confirm-credential screen (PIN / pattern /
            // password). A successful confirmation opens the key's window.
            var keyguard = _context.GetSystemService(Context.KeyguardService) as KeyguardManager;
#pragma warning disable CA1422 // The only way to confirm a device credential before API 30.
            var intent = keyguard?.CreateConfirmDeviceCredentialIntent("Approve sensitive operation", reason)
                         ?? throw new InstallationKeyException(
                             StepUpErrorCodes.NoDeviceCredential,
                             "Set a screen lock (PIN, pattern or password) to use step-up.");
#pragma warning restore CA1422
            lock (_gate)
            {
                _pendingConfirm = new PendingConfirm(entry, payload, done);
            }

            activity.StartActivityForResult(intent, ConfirmCredentialRequestCode);
        }

        [SupportedOSPlatform("android28.0")]
        private static BiometricPrompt BuildPrompt(
            Activity activity,
            string factor,
            string reason,
            Action<byte[]?, Exception?> done)
        {
            var builder = new BiometricPrompt.Builder(activity)
                .SetTitle("Approve sensitive operation")!
                .SetDescription(reason)!;
            var allowsCredential = factor == StepUpKeyAuth.FactorPasscode && OperatingSystem.IsAndroidVersionAtLeast(30);
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                builder = builder.SetAllowedAuthenticators(allowsCredential
                    ? (int)BiometricManagerAuthenticators.DeviceCredential
                    : (int)BiometricManagerAuthenticators.BiometricStrong)!;
            }

            if (!allowsCredential)
            {
                // A biometric-only prompt must offer its own way out; a
                // device-credential prompt must not (the system provides one).
                builder = builder.SetNegativeButton(
                    "Cancel",
                    activity.MainExecutor!,
                    new NegativeButton(() => done(null, new InstallationKeyException(
                        StepUpErrorCodes.Cancelled,
                        "The biometric prompt was cancelled."))))!;
            }

            return builder.Build()!;
        }

        private static byte[] SignNow(KeyStore.PrivateKeyEntry entry, byte[] payload)
        {
            // SHA256withECDSA from AndroidKeyStore is ASN.1 DER, which is what
            // the server verifies. No re-encoding.
            var signer = Signature.GetInstance("SHA256withECDSA")!;
            signer.InitSign(entry.PrivateKey);
            signer.Update(payload);
            return signer.Sign()
                   ?? throw new InstallationKeyException(
                       StepUpErrorCodes.SigningFailed,
                       "AndroidKeyStore returned no step-up signature.");
        }

        private void SignAndReport(KeyStore.PrivateKeyEntry entry, byte[] payload, Action<byte[]?, Exception?> done)
        {
            try
            {
                done(SignNow(entry, payload), null);
            }
            catch (KeyPermanentlyInvalidatedException error)
            {
                done(null, DiscardDeadKey(error));
            }
            catch (UserNotAuthenticatedException error)
            {
                done(null, new InstallationKeyException(
                    StepUpErrorCodes.AuthFailed,
                    "The keystore did not accept the authentication for the step-up key.",
                    error));
            }
            catch (GeneralSecurityException error)
            {
                done(null, SigningFailed(error));
            }
            catch (InstallationKeyException error)
            {
                done(null, error);
            }
        }

        private static InstallationKeyException SigningFailed(Exception error)
        {
            return new InstallationKeyException(
                StepUpErrorCodes.SigningFailed,
                "AndroidKeyStore could not sign with the step-up key: " + error.Message,
                error);
        }

        /// <summary>
        /// Deletes a step-up key that can never sign again, and says whether the
        /// removal actually happened: on the OPPO (Android 9) a dead key's alias
        /// survived <c>deleteEntry</c> while the screen lock was off.
        /// </summary>
        private InstallationKeyException DiscardDeadKey(Exception cause)
        {
            string removal;
            try
            {
                var keyStore = LoadKeyStore();
                keyStore.DeleteEntry(_keyAlias);
                removal = keyStore.ContainsAlias(_keyAlias)
                    ? "could not be removed (alias still present)"
                    : "has been removed";
            }
            catch (Exception error)
            {
                removal = "could not be removed (" + error.GetType().Name + ": " + error.Message + ")";
            }

            return new InstallationKeyException(
                StepUpErrorCodes.KeyInvalidated,
                "The step-up key was invalidated (the screen lock or enrolled biometrics changed) and "
                + removal + ". Re-enrol it to get a new one. [cause " + cause.GetType().Name + "]",
                cause);
        }

        // ------------------------------------------------------- key material

        private void GenerateKeyPair(KeyStore keyStore, StepUpKeyAuth requested)
        {
            var canTryStrongBox = OperatingSystem.IsAndroidVersionAtLeast(28)
                                  && _context.PackageManager?.HasSystemFeature(
                                      global::Android.Content.PM.PackageManager.FeatureStrongboxKeystore) == true;
            if (canTryStrongBox)
            {
                try
                {
                    GenerateKeyPair(requested, preferStrongBox: true);
                    return;
                }
                catch (Exception)
                {
                    // Same fallback as the installation key: remove any partial
                    // alias and retry with the regular provider.
                    try
                    {
                        if (keyStore.ContainsAlias(_keyAlias))
                        {
                            keyStore.DeleteEntry(_keyAlias);
                        }
                    }
                    catch (GeneralSecurityException)
                    {
                        // The regular attempt below produces the actionable error.
                    }
                }
            }

            GenerateKeyPair(requested, preferStrongBox: false);
        }

        private void GenerateKeyPair(StepUpKeyAuth requested, bool preferStrongBox)
        {
            try
            {
                var builder = new KeyGenParameterSpec.Builder(_keyAlias, KeyStorePurpose.Sign)
                    .SetAlgorithmParameterSpec(new ECGenParameterSpec(CurveName))!
                    .SetDigests(KeyProperties.DigestSha256)!
                    .SetUserAuthenticationRequired(true)!;

                var windowed = requested.Mode == StepUpKeyAuth.ModeWindowed;
                if (OperatingSystem.IsAndroidVersionAtLeast(30))
                {
                    builder = builder.SetUserAuthenticationParameters(
                        windowed ? requested.WindowSeconds : 0,
                        requested.Factor == StepUpKeyAuth.FactorBiometric
                            ? (int)KeyPropertiesAuthType.BiometricStrong
                            : (int)KeyPropertiesAuthType.DeviceCredential)!;
                }
                else
                {
#pragma warning disable CA1422 // The only window setter before API 30.
                    if (requested.Factor == StepUpKeyAuth.FactorPasscode)
                    {
                        // Option 1 fallback: no per-operation device credential
                        // before API 30, so a short hardware window is the
                        // strongest binding available.
                        builder = builder.SetUserAuthenticationValidityDurationSeconds(
                            windowed ? requested.WindowSeconds : StepUpKeyAuth.LegacyWindowSeconds)!;
                    }
                    else if (windowed)
                    {
                        builder = builder.SetUserAuthenticationValidityDurationSeconds(requested.WindowSeconds)!;
                    }

                    // else: biometric per-use before API 30 keeps the default (-1),
                    // which demands a biometric for every operation.
#pragma warning restore CA1422
                }

                if (requested.Factor == StepUpKeyAuth.FactorBiometric && OperatingSystem.IsAndroidVersionAtLeast(24))
                {
                    builder = builder.SetInvalidatedByBiometricEnrollment(true)!;
                }

                if (preferStrongBox && OperatingSystem.IsAndroidVersionAtLeast(28))
                {
                    builder = builder.SetIsStrongBoxBacked(true)!;
                }

                var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStoreName)
                                ?? throw new InstallationKeyException(
                                    StepUpErrorCodes.KeyGenerationFailed,
                                    "The EC key pair generator is unavailable.");
                generator.Initialize(builder.Build());
                generator.GenerateKeyPair();
            }
            catch (InstallationKeyException)
            {
                throw;
            }
            catch (Exception error)
            {
                throw new InstallationKeyException(
                    StepUpErrorCodes.KeyGenerationFailed,
                    "AndroidKeyStore could not create the step-up key: " + error.Message,
                    error);
            }
        }

        private static void RequireSupportedAndroid()
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(23))
            {
                throw new InstallationKeyException(
                    "UNSUPPORTED_ANDROID_VERSION",
                    "Step-up requires Android 6.0 (API 23) or newer.");
            }
        }

        private void RequireDeviceCredential()
        {
            var keyguard = _context.GetSystemService(Context.KeyguardService) as KeyguardManager;
            if (keyguard is null || !keyguard.IsDeviceSecure)
            {
                throw new InstallationKeyException(
                    StepUpErrorCodes.NoDeviceCredential,
                    "Set a screen lock (PIN, pattern or password) to enable step-up.");
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
                throw new InstallationKeyException("KEYSTORE_UNAVAILABLE", "AndroidKeyStore is unavailable.", error);
            }
        }

        /// <summary>
        /// Loads the stored step-up key, removing it if it has died in place. Any
        /// other lookup failure is reported with its cause and the key is kept.
        /// </summary>
        private KeyStore.PrivateKeyEntry LiveEntry(KeyStore keyStore)
        {
            KeyStore.IEntry? loaded;
            try
            {
                loaded = keyStore.GetEntry(_keyAlias, null);
            }
            catch (UnrecoverableKeyException error)
            {
                throw DiscardDeadKey(error);
            }
            catch (GeneralSecurityException error)
            {
                throw new InstallationKeyException(
                    "KEY_LOOKUP_FAILED",
                    "AndroidKeyStore could not load the step-up key: " + error.GetType().Name + ": " + error.Message,
                    error);
            }

            if (loaded is not KeyStore.PrivateKeyEntry entry || entry.PrivateKey is null)
            {
                throw DiscardDeadKey(new InvalidOperationException("The step-up alias no longer holds a private key."));
            }

            try
            {
                Signature.GetInstance("SHA256withECDSA")!.InitSign(entry.PrivateKey);
            }
            catch (KeyPermanentlyInvalidatedException error)
            {
                throw DiscardDeadKey(error);
            }
            catch (UserNotAuthenticatedException)
            {
                // Alive: a windowed key outside its window only needs authentication.
            }

            return entry;
        }

        private static KeyInfo KeyInfoOf(KeyStore.PrivateKeyEntry entry)
        {
            try
            {
                var factory = KeyFactory.GetInstance(entry.PrivateKey!.Algorithm!, AndroidKeyStoreName)!;
                return factory.GetKeySpec(entry.PrivateKey, Java.Lang.Class.FromType(typeof(KeyInfo))) as KeyInfo
                       ?? throw new InstallationKeyException(
                           "KEY_LOOKUP_FAILED",
                           "AndroidKeyStore could not describe the step-up key.");
            }
            catch (GeneralSecurityException error)
            {
                throw new InstallationKeyException(
                    "KEY_LOOKUP_FAILED",
                    "AndroidKeyStore could not describe the step-up key.",
                    error);
            }
        }

        /// <summary>What the keystore enforces for this key, read back from KeyInfo.</summary>
        private static StepUpKeyAuth DescribeAuth(KeyInfo info)
        {
            var duration = info.UserAuthenticationValidityDurationSeconds;
            var mode = duration > 0 ? StepUpKeyAuth.ModeWindowed : StepUpKeyAuth.ModePerUse;
            string factor;
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                factor = (info.UserAuthenticationType & (int)KeyPropertiesAuthType.DeviceCredential) != 0
                    ? StepUpKeyAuth.FactorPasscode
                    : StepUpKeyAuth.FactorBiometric;
            }
            else
            {
                // KeyInfo has no auth type before API 30. A per-use key can then
                // only be unlocked by a biometric; a windowed key by any
                // lock-screen authentication, and the store prompts for the
                // passcode.
                factor = mode == StepUpKeyAuth.ModePerUse
                    ? StepUpKeyAuth.FactorBiometric
                    : StepUpKeyAuth.FactorPasscode;
            }

            return new StepUpKeyAuth(factor, mode, duration > 0 ? Math.Min(duration, StepUpKeyAuth.MaxWindowSeconds) : 0);
        }

        private static (string Level, bool HardwareBacked) DescribeSecurity(KeyInfo info)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(31))
            {
                return (KeyStoreSecurityLevel)info.SecurityLevel switch
                {
                    KeyStoreSecurityLevel.Strongbox => ("strongbox", true),
                    KeyStoreSecurityLevel.TrustedEnvironment => ("trusted_execution_environment", true),
                    KeyStoreSecurityLevel.UnknownSecure => ("secure_hardware", true),
                    KeyStoreSecurityLevel.Software => ("software", false),
                    _ => ("unknown", false),
                };
            }

#pragma warning disable CA1422 // IsInsideSecureHardware is the only answer before API 31.
            return info.IsInsideSecureHardware ? ("secure_hardware", true) : ("software", false);
#pragma warning restore CA1422
        }

        private static byte[] UnsignedFixed(Java.Math.BigInteger value, int size)
        {
            var raw = value.ToByteArray() ?? Array.Empty<byte>();
            var offset = raw.Length == size + 1 && raw[0] == 0 ? 1 : 0;
            var length = raw.Length - offset;
            if (length > size)
            {
                throw new InstallationKeyException("INVALID_PUBLIC_KEY", "The EC coordinate is larger than P-256 permits.");
            }

            var output = new byte[size];
            Buffer.BlockCopy(raw, offset, output, size - length, length);
            return output;
        }

        private static InstallationKeyException PromptError(int errorCode, string? text)
        {
            // BIOMETRIC_ERROR_CANCELED (5) and BIOMETRIC_ERROR_USER_CANCELED (10).
            var cancelled = errorCode == 5 || errorCode == 10;
            return new InstallationKeyException(
                cancelled ? StepUpErrorCodes.Cancelled : StepUpErrorCodes.AuthFailed,
                "Step-up authentication did not complete: " + text + " (code " + errorCode + ")");
        }

        private sealed class PendingConfirm
        {
            public PendingConfirm(KeyStore.PrivateKeyEntry entry, byte[] payload, Action<byte[]?, Exception?> done)
            {
                Entry = entry;
                Payload = payload;
                Done = done;
            }

            public KeyStore.PrivateKeyEntry Entry { get; }

            public byte[] Payload { get; }

            public Action<byte[]?, Exception?> Done { get; }
        }

        [SupportedOSPlatform("android28.0")]
        private sealed class PromptCallback : BiometricPrompt.AuthenticationCallback
        {
            private readonly Action<BiometricPrompt.AuthenticationResult?> _succeeded;
            private readonly Action<Exception> _failed;

            public PromptCallback(Action<BiometricPrompt.AuthenticationResult?> succeeded, Action<Exception> failed)
            {
                _succeeded = succeeded;
                _failed = failed;
            }

            public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult? result)
            {
                _succeeded(result);
            }

            public override void OnAuthenticationError([GeneratedEnum] BiometricErrorCode errorCode, Java.Lang.ICharSequence? errString)
            {
                _failed(PromptError((int)errorCode, errString?.ToString()));
            }
        }

        private sealed class NegativeButton : Java.Lang.Object, IDialogInterfaceOnClickListener
        {
            private readonly Action _onClick;

            public NegativeButton(Action onClick)
            {
                _onClick = onClick;
            }

            public void OnClick(IDialogInterface? dialog, int which)
            {
                _onClick();
            }
        }
    }
}
