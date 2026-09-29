using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// The optional step-up key: a second non-exportable P-256 key that cannot
    /// sign without a fresh device authentication (DESIGN.md 51 and 53).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The installation key signs unattended, so on a compromised OS it can be
    /// driven as a silent signing oracle. The step-up key approves only the
    /// operations the server designates as sensitive, and the user has to be
    /// present for each one.
    /// </para>
    /// <para>
    /// It is optional by design. A device with no screen lock has no step-up
    /// key, and that must never fail enrolment: <see cref="GetOrCreateKeyAsync"/>
    /// throws <see cref="InstallationKeyException"/> with
    /// <see cref="StepUpErrorCodes.NoDeviceCredential"/>, the client records the
    /// key as unavailable, and the server refuses sensitive operations with
    /// <c>stepup_key_not_registered</c>.
    /// </para>
    /// <para>
    /// A key that has died in place — the screen lock was removed, or the
    /// enrolled biometrics changed — is deleted by the store and reported as
    /// <see cref="StepUpErrorCodes.KeyInvalidated"/>, saying truthfully whether
    /// the removal worked. The installation then needs re-enrolment
    /// (<c>POST /v1/installations/stepup-key</c>), because the server never
    /// accepts a replacement step-up key through registration.
    /// </para>
    /// </remarks>
    public interface IStepUpKeyStore
    {
        /// <summary>
        /// Returns the existing step-up key, or creates one protected as
        /// <paramref name="requested"/> asks where the platform can. The returned
        /// <see cref="StepUpKeyMetadata.Auth"/> is what the keystore enforces.
        /// An existing key is checked for death before the screen-lock
        /// requirement, since removing the lock is what kills it.
        /// </summary>
        Task<StepUpKeyMetadata> GetOrCreateKeyAsync(
            StepUpKeyAuth requested,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Asks the user to authenticate, then signs the exact bytes and returns
        /// an ASN.1 DER ECDSA-SHA256 signature.
        /// </summary>
        /// <param name="data">The step-up proof bytes.</param>
        /// <param name="reason">The text shown on the system prompt.</param>
        /// <param name="cancellationToken">Cancellation.</param>
        Task<byte[]> SignAsync(byte[] data, string reason, CancellationToken cancellationToken = default);

        /// <summary>Deletes the step-up key. Returns whether one existed.</summary>
        Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>The error codes step-up key stores report, shared across platforms.</summary>
    public static class StepUpErrorCodes
    {
        /// <summary>No screen lock is set, so no step-up key can exist.</summary>
        public const string NoDeviceCredential = "STEPUP_NO_DEVICE_CREDENTIAL";

        /// <summary>The biometric factor was requested but none is enrolled.</summary>
        public const string NoBiometric = "STEPUP_NO_BIOMETRIC";

        /// <summary>The key died in place and was discarded; re-enrolment is needed.</summary>
        public const string KeyInvalidated = "STEPUP_KEY_INVALIDATED";

        /// <summary>No step-up key exists to sign with.</summary>
        public const string KeyNotFound = "STEPUP_KEY_NOT_FOUND";

        /// <summary>The user dismissed the prompt.</summary>
        public const string Cancelled = "STEPUP_CANCELLED";

        /// <summary>The authentication did not succeed or was not accepted by the keystore.</summary>
        public const string AuthFailed = "STEPUP_AUTH_FAILED";

        /// <summary>Another step-up prompt is already showing.</summary>
        public const string Busy = "STEPUP_BUSY";

        /// <summary>The keystore failed to sign for another reason.</summary>
        public const string SigningFailed = "STEPUP_SIGNING_FAILED";

        /// <summary>The keystore could not create the key.</summary>
        public const string KeyGenerationFailed = "STEPUP_KEY_GENERATION_FAILED";

        /// <summary>The requested factor or mode cannot be provided on this OS version.</summary>
        public const string Unsupported = "STEPUP_UNSUPPORTED";

        /// <summary>No step-up key store was configured on the client.</summary>
        public const string NotConfigured = "STEPUP_NOT_CONFIGURED";
    }
}
