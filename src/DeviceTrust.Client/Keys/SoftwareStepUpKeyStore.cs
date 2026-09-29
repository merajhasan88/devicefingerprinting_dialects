using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// An in-memory step-up key that signs <b>without any user authentication</b>.
    /// Protocol testing only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The point of a step-up key is that it cannot sign unless the user is
    /// present. This one always can, so it proves nothing about step-up itself;
    /// it exists so the wire contract — the registration block, the step-up
    /// proof bound to the access-proof nonce, re-enrolment — can be exercised on
    /// a console or in CI, the same way the Python conformance suite uses a
    /// software key. The auth it reports is whatever it was told to claim, which
    /// is exactly the "client claim" limit DESIGN.md 51.2 describes.
    /// </para>
    /// <para>
    /// The constructor demands an explicit acknowledgement so no application
    /// selects it by accident. Use <c>AndroidStepUpKeyStore</c> or
    /// <c>SecureEnclaveStepUpKeyStore</c> in anything that makes a security claim.
    /// </para>
    /// </remarks>
    public sealed class SoftwareStepUpKeyStore : IStepUpKeyStore, IDisposable
    {
        private readonly object _gate = new object();
        private readonly StepUpKeyAuth? _claimedAuth;
        private ECDsa? _key;
        private StepUpKeyAuth? _auth;
        private bool _invalidated;

        /// <summary>Creates the store.</summary>
        /// <param name="acknowledgeNoUserAuthentication">
        /// Must be <c>true</c>: this key signs with nobody present.
        /// </param>
        /// <param name="claimedAuth">
        /// The auth to report regardless of what is requested, for tests that
        /// need a specific shape (the Android 9 windowed downgrade, say). Null
        /// reports what was requested.
        /// </param>
        public SoftwareStepUpKeyStore(bool acknowledgeNoUserAuthentication, StepUpKeyAuth? claimedAuth = null)
        {
            if (!acknowledgeNoUserAuthentication)
            {
                throw new InstallationKeyException(
                    "SOFTWARE_KEY_NOT_ACKNOWLEDGED",
                    "SoftwareStepUpKeyStore signs without any user authentication and must be selected "
                    + "deliberately by passing acknowledgeNoUserAuthentication: true.");
            }

            _claimedAuth = claimedAuth;
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
                if (_key is not null && _invalidated)
                {
                    throw DiscardDeadKey();
                }

                var created = false;
                if (_key is null)
                {
                    _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    _auth = _claimedAuth ?? requested;
                    created = true;
                }

                var parameters = _key.ExportParameters(false);
                return Task.FromResult(new StepUpKeyMetadata(
                    new EcPublicJsonWebKey(parameters.Q.X!, parameters.Q.Y!),
                    _auth!,
                    provider: "software-memory",
                    securityLevel: "software",
                    hardwareBacked: false,
                    created: created));
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
            lock (_gate)
            {
                if (_key is null)
                {
                    throw new InstallationKeyException(
                        StepUpErrorCodes.KeyNotFound,
                        "No step-up key exists on this installation.");
                }

                if (_invalidated)
                {
                    throw DiscardDeadKey();
                }

                return Task.FromResult(EcdsaSignatureFormat.SignDer(_key, data));
            }
        }

        /// <inheritdoc />
        public Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                var existed = _key is not null;
                _key?.Dispose();
                _key = null;
                _auth = null;
                _invalidated = false;
                return Task.FromResult(existed);
            }
        }

        /// <summary>
        /// Makes the key behave as a platform key does after the screen lock is
        /// removed: present, but unable to sign. For tests of the dead-key path.
        /// </summary>
        public void SimulateInvalidation()
        {
            lock (_gate)
            {
                _invalidated = _key is not null;
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

        private InstallationKeyException DiscardDeadKey()
        {
            _key?.Dispose();
            _key = null;
            _auth = null;
            _invalidated = false;
            return new InstallationKeyException(
                StepUpErrorCodes.KeyInvalidated,
                "The step-up key was invalidated and has been removed. Re-enrol it to get a new one.");
        }
    }
}
