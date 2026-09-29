using System;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Keys;
using Foundation;
using LocalAuthentication;
using Security;

namespace DeviceTrust.Client.Maui.Apple
{
    /// <summary>
    /// The optional step-up key in the Secure Enclave: a second P-256 key whose
    /// access control demands the device passcode (default) or the current
    /// biometric set for <b>every</b> signature (DESIGN.md 51 and 53).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A port of the Flutter client's <c>StepUpKeyManager</c> in
    /// <c>InstallationKeyManager.swift</c>. iOS is always per-use: each signature
    /// runs with a fresh <see cref="LAContext"/>, so an earlier authentication is
    /// never reused. There is no windowed mode, because iOS has no
    /// hardware-enforced reuse window for a passcode-gated key, and an app-level
    /// "authenticated recently?" check is what DESIGN.md 51.3 rules out.
    /// </para>
    /// <para>
    /// The key needs a passcode to exist (<c>WhenPasscodeSetThisDeviceOnly</c>).
    /// Removing the passcode did <b>not</b> delete it on the iPhone 7 (iOS
    /// 15.8.5): the public key stayed readable while every signature failed with
    /// CryptoTokenKit error -3, even after the passcode was set again
    /// (DESIGN.md 57). So a key is dead if it exists while iOS reports no
    /// passcode set (checked when the key is loaded), or if signing fails with
    /// CryptoTokenKit -3 (checked at use); either way it is deleted and
    /// <see cref="StepUpErrorCodes.KeyInvalidated"/> reported.
    /// </para>
    /// <para>
    /// The factor is recorded in the key's label at creation, so what is
    /// reported is what the key enforces.
    /// </para>
    /// </remarks>
    public sealed class SecureEnclaveStepUpKeyStore : IStepUpKeyStore
    {
        private const string DefaultTag = "com.devicetrust.stepup_key.v1";
        private const string LabelPrefix = "stepup:";
        private const int MaxPayloadBytes = 65536;

        // LAError.passcodeNotSet, and CryptoTokenKit's "corrupted data".
        private const long PasscodeNotSet = -5;
        private const long CryptoTokenKitCorruptedData = -3;
        private const string LocalAuthenticationErrorDomain = "com.apple.LocalAuthentication";
        private const string OsStatusErrorDomain = "NSOSStatusErrorDomain";

        private readonly string _applicationTag;
        private readonly object _gate = new object();

        /// <summary>Creates the store with the given keychain application tag.</summary>
        public SecureEnclaveStepUpKeyStore(string? applicationTag = null)
        {
            _applicationTag = string.IsNullOrWhiteSpace(applicationTag) ? DefaultTag : applicationTag!;
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
            lock (_gate)
            {
                var created = false;
                var key = LoadKey(null);
                if (key is not null && !DevicePasscodeSet())
                {
                    key.Dispose();
                    throw DiscardDeadKey("the device passcode was removed");
                }

                if (key is null)
                {
                    RequireFactorAvailable(requested.Factor);
                    key = GenerateKey(requested.Factor);
                    created = true;
                }

                using (key)
                {
                    return Task.FromResult(new StepUpKeyMetadata(
                        ReadPublicJwk(key),
                        new StepUpKeyAuth(StoredFactor() ?? requested.Factor, StepUpKeyAuth.ModePerUse, 0),
                        provider: "SecureEnclave",
                        securityLevel: "secure_enclave",
                        hardwareBacked: true,
                        created: created));
                }
            }
        }

        /// <inheritdoc />
        /// <remarks>
        /// Blocks until the user answers the system prompt, so the work runs off
        /// the calling thread.
        /// </remarks>
        public Task<byte[]> SignAsync(byte[] data, string reason, CancellationToken cancellationToken = default)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (data.Length > MaxPayloadBytes)
            {
                throw new InstallationKeyException(
                    "PAYLOAD_TOO_LARGE",
                    "The step-up payload is larger than " + MaxPayloadBytes + " bytes.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            return Task.Run(() => SignBlocking(data, reason ?? string.Empty), cancellationToken);
        }

        /// <inheritdoc />
        public Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                return Task.FromResult(DeleteKey());
            }
        }

        private byte[] SignBlocking(byte[] data, string reason)
        {
            // A fresh context per signature: an already-evaluated context would
            // be reused silently, and per-use is the whole point.
            using var context = new LAContext
            {
                LocalizedReason = reason,
                TouchIdAuthenticationAllowableReuseDuration = 0,
            };

            SecKey? key;
            lock (_gate)
            {
                key = LoadKey(context);
            }

            if (key is null)
            {
                throw new InstallationKeyException(
                    StepUpErrorCodes.KeyNotFound,
                    "No step-up key exists on this installation.");
            }

            using (key)
            using (var payload = NSData.FromArray(data))
            {
                var signature = key.CreateSignature(
                    SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
                    payload,
                    out var error);
                if (signature is not null && error is null)
                {
                    using (signature)
                    {
                        return signature.ToArray();
                    }
                }

                if (error is not null && error.Domain == "CryptoTokenKit" && (long)error.Code == CryptoTokenKitCorruptedData)
                {
                    lock (_gate)
                    {
                        throw DiscardDeadKey("the Secure Enclave can no longer use it");
                    }
                }

                throw SignFailure(error);
            }
        }

        /// <summary>
        /// False only when iOS reports that no passcode is set; any other answer
        /// is treated as "set", so a live key is never removed on a guess.
        /// </summary>
        private static bool DevicePasscodeSet()
        {
            using var context = new LAContext();
            if (context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out var error))
            {
                return true;
            }

            return error is null || (long)error.Code != PasscodeNotSet;
        }

        private static void RequireFactorAvailable(string factor)
        {
            using var context = new LAContext();
            var policy = factor == StepUpKeyAuth.FactorBiometric
                ? LAPolicy.DeviceOwnerAuthenticationWithBiometrics
                : LAPolicy.DeviceOwnerAuthentication;
            if (!context.CanEvaluatePolicy(policy, out _))
            {
                throw factor == StepUpKeyAuth.FactorBiometric
                    ? new InstallationKeyException(
                        StepUpErrorCodes.NoBiometric,
                        "Enrol Touch ID or Face ID to enable biometric step-up.")
                    : new InstallationKeyException(
                        StepUpErrorCodes.NoDeviceCredential,
                        "Set a device passcode to enable step-up.");
            }
        }

        /// <summary>
        /// Deletes a step-up key that can never sign again, saying truthfully
        /// whether the removal worked. Callers hold <see cref="_gate"/>.
        /// </summary>
        private InstallationKeyException DiscardDeadKey(string reason)
        {
            string removal;
            try
            {
                DeleteKey();
                using var still = LoadKey(null);
                removal = still is null ? "has been removed" : "could not be removed (still present)";
            }
            catch (Exception error)
            {
                removal = "could not be removed (" + error.Message + ")";
            }

            return new InstallationKeyException(
                StepUpErrorCodes.KeyInvalidated,
                "The step-up key was invalidated (" + reason + ") and " + removal
                + ". Re-enrol it to get a new one.");
        }

        private bool DeleteKey()
        {
            using var query = BuildQuery();
            var status = SecKeyChain.Remove(query);
            if (status == SecStatusCode.Success)
            {
                return true;
            }

            if (status == SecStatusCode.ItemNotFound)
            {
                return false;
            }

            throw new InstallationKeyException(
                "KEY_DELETE_FAILED",
                "The keychain could not delete the step-up key: " + status);
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

        private SecKey? LoadKey(LAContext? context)
        {
            using var query = BuildQuery();
            if (context is not null)
            {
                query.AuthenticationContext = context;
            }

            // The single-item call; see SecureEnclaveInstallationKeyStore for why
            // the array-returning QueryAsReference aborts once a key exists.
            var match = SecKeyChain.QueryAsConcreteType(query, out var status);
            if (status == SecStatusCode.ItemNotFound)
            {
                return null;
            }

            if (status != SecStatusCode.Success)
            {
                throw new InstallationKeyException(
                    "KEY_LOOKUP_FAILED",
                    "The keychain could not load the step-up key: " + status);
            }

            return match as SecKey
                   ?? throw new InstallationKeyException(
                       "KEY_LOOKUP_FAILED",
                       "The keychain returned an item that is not a key.");
        }

        private string? StoredFactor()
        {
            using var query = BuildQuery();
            using var record = SecKeyChain.QueryAsRecord(query, out var status);
            var label = status == SecStatusCode.Success ? record?.Label : null;
            return label is not null && label.StartsWith(LabelPrefix, StringComparison.Ordinal)
                ? label.Substring(LabelPrefix.Length)
                : null;
        }

        private SecKey GenerateKey(string factor)
        {
            var flags = factor == StepUpKeyAuth.FactorBiometric
                ? SecAccessControlCreateFlags.PrivateKeyUsage | SecAccessControlCreateFlags.BiometryCurrentSet
                : SecAccessControlCreateFlags.PrivateKeyUsage | SecAccessControlCreateFlags.DevicePasscode;

            var parameters = new SecKeyGenerationParameters
            {
                KeyType = SecKeyType.ECSecPrimeRandom,
                KeySizeInBits = 256,
                TokenID = SecTokenID.SecureEnclave,
                PrivateKeyAttrs = new SecKeyParameters
                {
                    IsPermanent = true,
                    ApplicationTag = NSData.FromString(_applicationTag, NSStringEncoding.UTF8),
                    Label = LabelPrefix + factor,
                    AccessControl = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly, flags),
                },
            };

            var key = SecKey.CreateRandomKey(parameters, out var error);
            if (key is null || error is not null)
            {
                throw new InstallationKeyException(
                    StepUpErrorCodes.KeyGenerationFailed,
                    "The Secure Enclave could not create the step-up key: "
                    + (error?.LocalizedDescription ?? "unknown error"));
            }

            return key;
        }

        private static EcPublicJsonWebKey ReadPublicJwk(SecKey privateKey)
        {
            using var publicKey = privateKey.GetPublicKey()
                                  ?? throw new InstallationKeyException(
                                      "INVALID_PUBLIC_KEY",
                                      "The keychain returned no public key for the step-up key.");
            using var representation = publicKey.GetExternalRepresentation(out var error);
            var bytes = representation?.ToArray();
            if (bytes is null || error is not null || bytes.Length != 65 || bytes[0] != 0x04)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The step-up public key is not an uncompressed P-256 point.");
            }

            var x = new byte[32];
            var y = new byte[32];
            Buffer.BlockCopy(bytes, 1, x, 0, 32);
            Buffer.BlockCopy(bytes, 33, y, 0, 32);
            return new EcPublicJsonWebKey(x, y);
        }

        private static InstallationKeyException SignFailure(NSError? error)
        {
            if (error is null)
            {
                return new InstallationKeyException(
                    StepUpErrorCodes.SigningFailed,
                    "The Secure Enclave could not sign with the step-up key.");
            }

            var domain = error.Domain;
            var code = (long)error.Code;
            var text = error.LocalizedDescription ?? "unknown error";

            // errSecUserCanceled; LAError userCancel, systemCancel, appCancel.
            if ((domain == OsStatusErrorDomain && code == -128)
                || (domain == LocalAuthenticationErrorDomain && (code == -2 || code == -4 || code == -9)))
            {
                return new InstallationKeyException(
                    StepUpErrorCodes.Cancelled,
                    "Step-up authentication was cancelled: " + text);
            }

            // errSecAuthFailed, or any other LocalAuthentication failure.
            if ((domain == OsStatusErrorDomain && code == -25293) || domain == LocalAuthenticationErrorDomain)
            {
                return new InstallationKeyException(
                    StepUpErrorCodes.AuthFailed,
                    "Step-up authentication failed: " + text);
            }

            return new InstallationKeyException(
                StepUpErrorCodes.SigningFailed,
                "The Secure Enclave could not sign with the step-up key: " + text + " (" + domain + " " + code + ")");
        }
    }
}
