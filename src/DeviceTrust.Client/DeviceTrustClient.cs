using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Protocol;
using DeviceTrust.Client.Storage;

namespace DeviceTrust.Client
{
    /// <summary>
    /// The device-trust client: installation identity, proof of possession,
    /// per-request access proofs, signed integrity reports and refresh rotation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the type an application embeds. It mirrors the Flutter reference
    /// client's controller, and the call order it enforces is the protocol's own:
    /// register the public key, prove possession of the private key to obtain a
    /// 10-minute device token, submit a signed integrity report, then open or
    /// authenticate an account and make protected calls that each carry a fresh
    /// single-use proof.
    /// </para>
    /// <para>
    /// Nothing here is a security decision. Every verdict — recognition,
    /// integrity score, relationship risk, whether a request is allowed — is made
    /// by the server. The client's job is to produce honest measurements and
    /// correct signatures.
    /// </para>
    /// </remarks>
    public sealed class DeviceTrustClient : IDisposable
    {
        private readonly DeviceTrustOptions _options;
        private readonly IInstallationKeyStore _keyStore;
        private readonly IInstallationStateStore _stateStore;
        private readonly IIntegrityProbeCollector? _integrityCollector;
        private readonly IStepUpKeyStore? _stepUpKeyStore;
        private readonly DeviceTrustApi _api;
        private readonly SemaphoreSlim _identityGate = new SemaphoreSlim(1, 1);

        private InstallationIdentity? _identity;

        /// <summary>Creates a client.</summary>
        /// <param name="options">Endpoint and behaviour configuration.</param>
        /// <param name="keyStore">The platform key store holding the installation key.</param>
        /// <param name="stateStore">Where the installation UUID and tokens are kept between launches.</param>
        /// <param name="integrityCollector">
        /// The native measurement collector. Optional only because the identity,
        /// possession and access-proof flows work without it; a server in
        /// <c>INTEGRITY_MODE=enforce</c> will refuse account operations until a
        /// fresh signed report exists.
        /// </param>
        /// <param name="httpClient">An externally owned <see cref="HttpClient"/>, if the host has one.</param>
        /// <param name="stepUpKeyStore">
        /// The optional step-up key store (DESIGN.md 53). Without one the client
        /// registers no step-up key and the server refuses sensitive operations
        /// with <c>stepup_key_not_registered</c>.
        /// </param>
        public DeviceTrustClient(
            DeviceTrustOptions options,
            IInstallationKeyStore keyStore,
            IInstallationStateStore? stateStore = null,
            IIntegrityProbeCollector? integrityCollector = null,
            HttpClient? httpClient = null,
            IStepUpKeyStore? stepUpKeyStore = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _stateStore = stateStore ?? new InMemoryInstallationStateStore();
            _integrityCollector = integrityCollector;
            _stepUpKeyStore = stepUpKeyStore;
            _api = new DeviceTrustApi(options, httpClient);

            Platform = options.Platform
                       ?? integrityCollector?.Platform
                       ?? throw new DeviceTrustConfigurationException(
                           "No platform was configured and no integrity collector was supplied to imply one. "
                           + "Set DeviceTrustOptions.Platform, or pass a collector whose Platform names what it "
                           + "can actually measure.",
                           "platform_missing");
        }

        /// <summary>The raw endpoint surface, for callers that need it directly.</summary>
        public DeviceTrustApi Api => _api;

        /// <summary>
        /// The platform this client registers under. It comes from the integrity
        /// collector unless explicitly overridden, so the identity a device claims
        /// and the measurements it can produce always describe the same thing.
        /// </summary>
        public string Platform { get; }

        /// <summary>The current installation identity, once loaded.</summary>
        public InstallationIdentity? Identity => _identity;

        /// <summary>The most recent registration answer.</summary>
        public RegistrationState? Registration { get; private set; }

        /// <summary>The current 10-minute device token, if one has been obtained.</summary>
        public string? DeviceToken { get; private set; }

        /// <summary>The current account session, if one has been opened.</summary>
        public AccountSession? Session { get; private set; }

        /// <summary>The most recent device record the server returned.</summary>
        public DeviceSummary? DeviceRecord { get; private set; }

        /// <summary>The most recent integrity decision.</summary>
        public IntegrityDecision? LatestIntegrity { get; private set; }

        /// <summary>The probes the server last asked for.</summary>
        public IReadOnlyList<string> LastRequiredProbes { get; private set; } = Array.Empty<string>();

        /// <summary>
        /// The measurements the collector produced for the most recent report.
        /// </summary>
        /// <remarks>
        /// Exposed so a caller can display or log what was actually sent without
        /// running the collector a second time. That matters more than
        /// convenience: some probes are not free and not perfectly side-effect
        /// free — the Android code-integrity probe temporarily lifts PROT_READ on
        /// execute-only system libraries — so a caller that re-measured for
        /// display would double that work on every scan.
        /// </remarks>
        public IntegrityCollection? LastIntegrityCollection { get; private set; }

        /// <summary>The local step-up key, once prepared; null when there is none.</summary>
        public StepUpKeyMetadata? StepUpKey { get; private set; }

        /// <summary>
        /// Why there is no local step-up key — no screen lock, a key that died,
        /// no store configured — or null when there is one.
        /// </summary>
        public InstallationKeyException? StepUpUnavailable { get; private set; }

        /// <summary>
        /// The thumbprint of the step-up key the server last confirmed as bound
        /// to this installation, or null when it has confirmed none.
        /// </summary>
        /// <remarks>
        /// Set at each registration from the key this client offered: bound
        /// there (a new installation binds the offered key) or reported as
        /// matching (a known installation). A registration that offered no key
        /// confirms nothing, even though the server still holds one, because
        /// "not asked" is not "matches" (DESIGN.md 63.10).
        /// </remarks>
        public string? BoundStepUpThumbprint { get; private set; }

        /// <summary>
        /// Whether a step-up signature from this device will be accepted: the
        /// local key is the one the server last confirmed as bound. Offer the
        /// step-up action only when this is true; otherwise offer re-enrolment.
        /// </summary>
        /// <remarks>
        /// Found on the reference iPhone, 2026-10-04: with the passcode off at
        /// launch no key was offered at registration (<c>stepup_key_matches</c>
        /// null); with it back on, a refused re-enrolment left a fresh, unbound
        /// key behind, and a rule that excluded only a key reported as different
        /// offered that one for step-up. The server refused its signature with
        /// <c>stepup_signature_invalid</c>, correctly.
        /// </remarks>
        public bool StepUpUsable => StepUpKey is not null
                                    && BoundStepUpThumbprint is not null
                                    && string.Equals(StepUpKey.Thumbprint, BoundStepUpThumbprint, StringComparison.Ordinal);

        /// <summary>
        /// Loads the installation identity, creating the key and the UUID if this
        /// is a first run.
        /// </summary>
        /// <remarks>
        /// When a stored UUID survives but the key does not — an uninstall that
        /// cleared the keystore, a wiped key, a restored backup — the UUID is
        /// replaced rather than reused. Presenting an old UUID with a new public
        /// key is exactly the collision the server refuses, and the reinstall
        /// hint is what correlates the fresh installation back to the same
        /// device.
        /// </remarks>
        public async Task<InstallationIdentity> LoadIdentityAsync(CancellationToken cancellationToken = default)
        {
            await _identityGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_identity is not null)
                {
                    return _identity;
                }

                var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
                var metadata = await _keyStore.GetOrCreateKeyAsync(cancellationToken).ConfigureAwait(false);

                if (metadata.Created)
                {
                    // A new installation key is a new server installation, and a
                    // step-up key binds only at first registration: rotate it so
                    // the new installation enrols its own rather than offering a
                    // key the server will report as not matching.
                    await DeleteStepUpKeyQuietlyAsync(cancellationToken).ConfigureAwait(false);
                }

                var hadInstallationId = !string.IsNullOrEmpty(state.InstallationId);
                if (!hadInstallationId)
                {
                    state.InstallationId = Guid.NewGuid().ToString();
                    await _stateStore.SaveAsync(state, cancellationToken).ConfigureAwait(false);
                }
                else if (metadata.Created)
                {
                    state.InstallationId = Guid.NewGuid().ToString();
                    state.AccessToken = null;
                    state.RefreshToken = null;
                    state.AccountId = null;
                    state.DeviceId = null;
                    state.KeyThumbprint = null;
                    await _stateStore.SaveAsync(state, cancellationToken).ConfigureAwait(false);
                }

                _identity = new InstallationIdentity(state.InstallationId!, metadata);
                return _identity;
            }
            finally
            {
                _identityGate.Release();
            }
        }

        /// <summary>Registers the installation's public key with the server.</summary>
        public async Task<RegistrationState> RegisterInstallationAsync(
            ReinstallHint? reinstallHint = null,
            CancellationToken cancellationToken = default)
        {
            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);
            await PrepareStepUpKeyAsync(cancellationToken).ConfigureAwait(false);

            RegistrationState registration;
            try
            {
                registration = await _api.RegisterInstallationAsync(
                    identity.InstallationId,
                    Platform,
                    identity.Key.PublicKey,
                    reinstallHint,
                    identity.Key,
                    StepUpKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (DeviceTrustApiException error) when (error.Code == "registration_race_retry")
            {
                // Two installations raced on the same reinstall hint. The server
                // rolled its transaction back and asked for exactly one retry.
                registration = await _api.RegisterInstallationAsync(
                    identity.InstallationId,
                    Platform,
                    identity.Key.PublicKey,
                    reinstallHint,
                    identity.Key,
                    StepUpKey,
                    cancellationToken).ConfigureAwait(false);
            }

            if (!string.Equals(registration.InstallationId, identity.InstallationId, StringComparison.Ordinal))
            {
                // The server already knew this key and answered with the
                // installation it is bound to. Adopt it: the thumbprint is the
                // identity, not our UUID.
                _identity = identity.WithInstallationId(registration.InstallationId);
            }

            Registration = registration;
            var offered = StepUpKey;
            BoundStepUpThumbprint = offered is not null
                                    && registration.StepUpKeyRegistered
                                    && registration.StepUpKeyMatches != false
                ? offered.Thumbprint
                : null;

            var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            state.InstallationId = registration.InstallationId;
            state.DeviceId = registration.DeviceId;
            state.KeyThumbprint = registration.KeyThumbprint;
            await _stateStore.SaveAsync(state, cancellationToken).ConfigureAwait(false);

            return registration;
        }

        /// <summary>
        /// Proves possession of the installation key and returns a 10-minute
        /// device token.
        /// </summary>
        public async Task<string> AcquireDeviceTokenAsync(CancellationToken cancellationToken = default)
        {
            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);

            var challenge = await _api.CreateInstallationChallengeAsync(identity.InstallationId, cancellationToken)
                .ConfigureAwait(false);
            var challengeId = Json.RequireString(challenge, "challenge_id");
            var payload = Json.RequireString(challenge, "payload");

            // The server signs nothing here: it stored the SHA-256 of the payload
            // it issued and compares. We sign the decoded bytes, which is what the
            // server verifies against the registered public key.
            var signature = await SignBase64UrlPayloadAsync(payload, cancellationToken).ConfigureAwait(false);

            var verified = await _api.VerifyInstallationAsync(
                identity.InstallationId,
                challengeId,
                payload,
                signature,
                cancellationToken).ConfigureAwait(false);

            DeviceToken = Json.RequireString(verified, "device_token");
            return DeviceToken;
        }

        /// <summary>
        /// Runs one complete integrity round trip: challenge, collect, sign,
        /// submit.
        /// </summary>
        /// <param name="bearerToken">A device or account token to authenticate the two calls.</param>
        /// <param name="cancellationToken">Cancellation.</param>
        public async Task<IntegrityDecision> SubmitIntegrityReportAsync(
            string bearerToken,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(bearerToken))
            {
                throw new ArgumentException("A bearer token is required.", nameof(bearerToken));
            }

            if (_integrityCollector is null)
            {
                throw new DeviceTrustConfigurationException(
                    "No integrity collector was supplied, so this client cannot produce a report. "
                    + "A server in enforce mode will refuse account operations without one.",
                    "integrity_collector_missing");
            }

            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);

            var challengeResponse = await SendProtectedAsync(
                "POST",
                "/v1/integrity/challenge",
                Array.Empty<byte>(),
                bearerToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var challenge = IntegrityChallenge.Parse(challengeResponse);
            LastRequiredProbes = challenge.RequiredProbes;

            var collection = await _integrityCollector.CollectAsync(
                challenge.RequiredProbes,
                challenge.Nonce,
                cancellationToken).ConfigureAwait(false);

            // Check the binding locally before signing. A collector that answered
            // a different challenge would otherwise produce a correctly signed
            // report that the server has to reject, which is a much harder failure
            // to read than this one.
            if (!string.Equals(collection.Platform, challenge.Platform, StringComparison.Ordinal)
                || !string.Equals(collection.ChallengeNonceEcho, challenge.Nonce, StringComparison.Ordinal))
            {
                throw new DeviceTrustProtocolException(
                    "The integrity collector's response did not match the server challenge.",
                    "integrity_challenge_binding_failed");
            }

            LastIntegrityCollection = collection;

            var reportBytes = BuildIntegrityReport(challenge, collection, identity.InstallationId);
            var reportPayload = Base64Url.Encode(reportBytes);
            var reportSignature = Base64Url.Encode(
                await _keyStore.SignAsync(reportBytes, cancellationToken).ConfigureAwait(false));

            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["report_payload"] = reportPayload,
                ["report_signature"] = reportSignature,
            });

            var response = await SendProtectedAsync(
                "POST",
                "/v1/integrity/report",
                body,
                bearerToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var decision = Json.GetObject(response, "integrity")
                           ?? throw new DeviceTrustProtocolException(
                               "The server returned no integrity decision.",
                               "missing_integrity_decision");

            LatestIntegrity = IntegrityDecision.Parse(decision);
            return LatestIntegrity;
        }

        /// <summary>Reads the server's record of this installation and device.</summary>
        public async Task<DeviceSummary> GetDeviceSummaryAsync(
            string bearerToken,
            CancellationToken cancellationToken = default)
        {
            var response = await SendProtectedAsync(
                "GET",
                "/v1/device/me",
                null,
                bearerToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            DeviceRecord = DeviceSummary.Parse(response);
            return DeviceRecord;
        }

        /// <summary>
        /// Registers, proves possession, reports integrity and reads the device
        /// record — the sequence a real client runs at launch.
        /// </summary>
        public async Task BootstrapAsync(
            ReinstallHint? reinstallHint = null,
            CancellationToken cancellationToken = default)
        {
            await RegisterInstallationAsync(reinstallHint, cancellationToken).ConfigureAwait(false);
            var token = await AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            if (_integrityCollector is not null)
            {
                await SubmitIntegrityReportAsync(token, cancellationToken).ConfigureAwait(false);
            }

            await GetDeviceSummaryAsync(token, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Opens an account on this device using a fresh device token.</summary>
        public Task<AccountSession> RegisterAccountAsync(
            string handle,
            string password,
            CancellationToken cancellationToken = default)
        {
            return OpenAccountAsync("/v1/accounts/register", handle, password, cancellationToken);
        }

        /// <summary>Authenticates an existing account and links it to this device.</summary>
        public Task<AccountSession> LoginAccountAsync(
            string handle,
            string password,
            CancellationToken cancellationToken = default)
        {
            return OpenAccountAsync("/v1/accounts/login", handle, password, cancellationToken);
        }

        /// <summary>Calls <c>GET /v1/account/me</c> with an access proof.</summary>
        public Task<JsonElement> GetAccountMeAsync(CancellationToken cancellationToken = default)
        {
            return SendProtectedAsync("GET", "/v1/account/me", null, RequireSession().AccessToken,
                cancellationToken: cancellationToken);
        }

        /// <summary>Calls <c>POST /v1/account/protected-echo</c> with an access proof over the body.</summary>
        public Task<JsonElement> ProtectedEchoAsync(
            IReadOnlyDictionary<string, object?> body,
            CancellationToken cancellationToken = default)
        {
            if (body is null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            return SendProtectedAsync(
                "POST",
                "/v1/account/protected-echo",
                Json.SerializeToUtf8Bytes(body),
                RequireSession().AccessToken,
                cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Calls the demo crown-jewel endpoint <c>POST /v1/account/sensitive-echo</c>,
        /// with or without a step-up proof.
        /// </summary>
        /// <remarks>
        /// The endpoint requires step-up only when the deployment lists it in
        /// <c>risk_policy_settings.stepup_required_paths</c>; otherwise it answers
        /// <c>step_up: not_required</c>. Without step-up on a gated path the
        /// server answers <c>403 stepup_required</c>.
        /// </remarks>
        public Task<JsonElement> SensitiveEchoAsync(
            IReadOnlyDictionary<string, object?> body,
            bool withStepUp,
            string reason = "Approve a sensitive operation",
            CancellationToken cancellationToken = default)
        {
            if (body is null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            var encoded = Json.SerializeToUtf8Bytes(body);
            var accessToken = RequireSession().AccessToken;
            return withStepUp
                ? SendStepUpProtectedAsync("POST", "/v1/account/sensitive-echo", encoded, accessToken, reason,
                    cancellationToken)
                : SendProtectedAsync("POST", "/v1/account/sensitive-echo", encoded, accessToken,
                    cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Sends a protected request that also carries a step-up proof: the user
        /// authenticates, the step-up key signs an approval of this exact
        /// request, and only then is the access proof signed.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Step-up proof v2 (DESIGN.md 63) approves one complete request: the
        /// token hash, method, path, query, body hash and the access proof's
        /// nonce, each compared by the server with the request it receives
        /// (<c>stepup_binding_mismatch</c> names any that differ). Version 1
        /// signed only the installation, factor and nonce, so whoever held the
        /// installation signer could move a fresh approval onto a different body
        /// under a re-signed access proof with the same nonce; the server now
        /// refuses it with <c>stepup_proof_version_unsupported</c>.
        /// </para>
        /// <para>
        /// The order is deliberate: the body and nonce are frozen first, the
        /// step-up proof is signed (the prompt can take a while), and the access
        /// proof is signed last so its ±120-second window starts after the user
        /// has answered. Both proofs are built from one description of the
        /// request, so they cannot disagree. A key found dead at signing is
        /// discarded by the store and <see cref="StepUpKey"/> is cleared, so the
        /// caller stops offering it.
        /// </para>
        /// </remarks>
        public async Task<JsonElement> SendStepUpProtectedAsync(
            string method,
            string path,
            byte[]? body,
            string bearerToken,
            string reason,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(bearerToken))
            {
                throw new ArgumentException("A bearer token is required.", nameof(bearerToken));
            }

            var key = StepUpKey ?? throw StepUpKeyMissing();
            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);
            var nonce = AccessProof.CreateNonce();
            var target = DescribeRequest(method, path, body);

            var proof = BuildStepUpProof(
                identity.InstallationId,
                Hex.Sha256Hex(bearerToken),
                target.Method,
                target.SignedPath,
                target.Query,
                AccessProof.BodyHash(target.Body),
                key.Auth.Factor,
                nonce,
                AccessProof.CurrentTimestamp());
            var signature = await SignWithStepUpKeyAsync(proof, reason, cancellationToken).ConfigureAwait(false);

            var fixture = await BuildAccessProofFixtureAsync(
                method,
                path,
                body,
                bearerToken,
                nonce: nonce,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!fixture.EncodedBody.AsSpan().SequenceEqual(target.Body))
            {
                // The approval covers these exact bytes; sending others would be
                // refused as stepup_binding_mismatch, so fail here instead.
                throw new DeviceTrustProtocolException(
                    "The request body changed after it was approved.",
                    "stepup_body_changed");
            }

            return await SendAccessProofFixtureAsync(
                fixture,
                additionalHeaders: new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [StepUpProofHeader] = Base64Url.Encode(proof),
                    [StepUpSignatureHeader] = Base64Url.Encode(signature),
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Binds this device's current step-up key to the installation for the
        /// signed-in account (<c>POST /v1/installations/stepup-key</c>, DESIGN.md 58).
        /// </summary>
        /// <remarks>
        /// <para>
        /// The recovery path when the step-up key was lost — the screen lock was
        /// removed, or the installation enrolled before it had one. The server
        /// accepts a new key only with all three of: the access proof, the
        /// account password entered now, and a signature by the new key over a
        /// proof naming its own thumbprint and this request's nonce, which the
        /// device grants only after the user passes the screen lock.
        /// </para>
        /// <para>
        /// The re-enrolled key is scoped to this account. Another account on the
        /// same installation gets <c>403 stepup_key_other_account</c> until it
        /// re-enrols with its own password. Afterwards the installation is
        /// re-registered so <see cref="Registration"/> shows the server's view.
        /// </para>
        /// </remarks>
        /// <returns>The server's answer: the key is registered, its auth, and any downgrade.</returns>
        public async Task<JsonElement> ReenrolStepUpKeyAsync(
            string password,
            ReinstallHint? reinstallHint = null,
            string reason = "Confirm your new step-up key",
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("The account password is required.", nameof(password));
            }

            var session = RequireSession();
            if (StepUpKey is null)
            {
                await PrepareStepUpKeyAsync(cancellationToken).ConfigureAwait(false);
            }

            var key = StepUpKey ?? throw StepUpKeyMissing();
            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);
            var nonce = AccessProof.CreateNonce();

            byte[] keyProof;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("version", 1);
                    writer.WriteString("purpose", "stepup_reenrol");
                    writer.WriteString("installation_id", identity.InstallationId);
                    writer.WriteString("stepup_key_thumbprint", key.Thumbprint);
                    writer.WriteString("nonce", nonce);
                    writer.WriteNumber("timestamp", AccessProof.CurrentTimestamp());
                    writer.WriteEndObject();
                }

                keyProof = buffer.ToArray();
            }

            var keySignature = await SignWithStepUpKeyAsync(keyProof, reason, cancellationToken).ConfigureAwait(false);

            byte[] body;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("password", password);
                    writer.WritePropertyName("stepup_public_key");
                    key.PublicKey.Write(writer);
                    writer.WritePropertyName("stepup_key_auth");
                    key.Auth.Write(writer);
                    writer.WriteString("stepup_key_proof", Base64Url.Encode(keyProof));
                    writer.WriteString("stepup_key_signature", Base64Url.Encode(keySignature));
                    writer.WriteEndObject();
                }

                body = buffer.ToArray();
            }

            var fixture = await BuildAccessProofFixtureAsync(
                "POST",
                "/v1/installations/stepup-key",
                body,
                session.AccessToken,
                nonce: nonce,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var response = await SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            await RegisterInstallationAsync(reinstallHint, cancellationToken).ConfigureAwait(false);
            return response;
        }

        /// <summary>
        /// Loads or creates the local step-up key. Never throws for an
        /// unavailable key: no screen lock, no store or a dead key is recorded in
        /// <see cref="StepUpUnavailable"/>, because a device without step-up must
        /// still enrol.
        /// </summary>
        public async Task<StepUpKeyMetadata?> PrepareStepUpKeyAsync(CancellationToken cancellationToken = default)
        {
            StepUpKey = null;
            StepUpUnavailable = null;
            if (_stepUpKeyStore is null)
            {
                StepUpUnavailable = new InstallationKeyException(
                    StepUpErrorCodes.NotConfigured,
                    "No step-up key store was configured for this client.");
                return null;
            }

            try
            {
                StepUpKey = await _stepUpKeyStore.GetOrCreateKeyAsync(_options.StepUp, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InstallationKeyException error)
            {
                StepUpUnavailable = error;
            }

            return StepUpKey;
        }

        /// <summary>Reads the current relationship-risk decision.</summary>
        public async Task<RiskPolicyDecision> GetPolicyAsync(CancellationToken cancellationToken = default)
        {
            var response = await SendProtectedAsync(
                "GET",
                "/v1/policy/me",
                null,
                RequireSession().AccessToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var policy = Json.GetObject(response, "policy")
                         ?? throw new DeviceTrustProtocolException(
                             "The server returned no policy decision.",
                             "missing_policy_decision");
            return RiskPolicyDecision.Parse(policy);
        }

        /// <summary>
        /// Rotates the refresh session: request a challenge with the refresh
        /// token, sign it with the installation key, exchange it for a new pair.
        /// </summary>
        /// <remarks>
        /// The challenge succeeding proves only that the refresh token is
        /// genuine. It is the signature over that challenge that proves the
        /// request comes from the device the token was issued to, which is why a
        /// stolen refresh token gets a 200 on the challenge and a 401 on the
        /// exchange. Reusing an already-rotated token revokes the whole family.
        /// </remarks>
        public async Task<AccountSession> RefreshAccountSessionAsync(CancellationToken cancellationToken = default)
        {
            var session = RequireSession();

            var challenge = await _api.RefreshChallengeAsync(session.RefreshToken, cancellationToken)
                .ConfigureAwait(false);
            var challengeId = Json.RequireString(challenge, "challenge_id");
            var payload = Json.RequireString(challenge, "payload");
            var signature = await SignBase64UrlPayloadAsync(payload, cancellationToken).ConfigureAwait(false);

            var rotated = await _api.RefreshAsync(
                session.RefreshToken,
                challengeId,
                payload,
                signature,
                cancellationToken).ConfigureAwait(false);

            await AdoptSessionAsync(rotated, cancellationToken).ConfigureAwait(false);
            return rotated;
        }

        /// <summary>
        /// Builds a signed access proof without sending it.
        /// </summary>
        /// <param name="method">The HTTP method to name in the proof.</param>
        /// <param name="path">
        /// The API path to name in the proof, optionally with a query string;
        /// the query is signed as the request will carry it (access proof v2).
        /// </param>
        /// <param name="body">The exact body bytes to hash into the proof; null for GET.</param>
        /// <param name="bearerToken">The token to bind the proof to.</param>
        /// <param name="proofInstallationId">
        /// Overrides the installation id written into the proof. Used only by the
        /// stolen-token test, which must claim the <i>victim's</i> installation id
        /// while signing with the <i>attacker's</i> key — otherwise the request
        /// fails on an id mismatch before it ever reaches the signature check, and
        /// proves nothing about key possession.
        /// </param>
        /// <param name="timestampSeconds">Overrides the timestamp, for the stale-proof test.</param>
        /// <param name="nonce">Overrides the nonce, for deterministic tests.</param>
        /// <param name="cancellationToken">Cancellation.</param>
        public async Task<AccessProofFixture> BuildAccessProofFixtureAsync(
            string method,
            string path,
            byte[]? body,
            string bearerToken,
            string? proofInstallationId = null,
            long? timestampSeconds = null,
            string? nonce = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(bearerToken))
            {
                throw new ArgumentException("A bearer token is required.", nameof(bearerToken));
            }

            var identity = await LoadIdentityAsync(cancellationToken).ConfigureAwait(false);
            var target = DescribeRequest(method, path, body);

            var proofBytes = AccessProof.Serialize(
                Hex.Sha256Hex(bearerToken),
                AccessProof.BodyHash(target.Body),
                proofInstallationId ?? identity.InstallationId,
                target.Method,
                nonce ?? AccessProof.CreateNonce(),
                target.SignedPath,
                target.Query,
                timestampSeconds ?? AccessProof.CurrentTimestamp());

            var signature = await _keyStore.SignAsync(proofBytes, cancellationToken).ConfigureAwait(false);

            using var document = JsonDocument.Parse(proofBytes);
            return new AccessProofFixture(
                bearerToken,
                target.Method,
                path,
                target.Body,
                Base64Url.Encode(proofBytes),
                Base64Url.Encode(signature),
                document.RootElement.GetProperty("timestamp").GetInt64(),
                document.RootElement.GetProperty("nonce").GetString()!);
        }

        /// <summary>
        /// Sends a previously built proof, optionally against a different
        /// request than the one it was signed for.
        /// </summary>
        public Task<JsonElement> SendAccessProofFixtureAsync(
            AccessProofFixture fixture,
            string? actualMethod = null,
            string? actualPath = null,
            byte[]? actualBody = null,
            IReadOnlyDictionary<string, string>? additionalHeaders = null,
            CancellationToken cancellationToken = default)
        {
            if (fixture is null)
            {
                throw new ArgumentNullException(nameof(fixture));
            }

            var method = (actualMethod ?? fixture.SignedMethod).ToUpperInvariant();
            var path = actualPath ?? fixture.SignedPath;
            var body = method == "GET" ? null : actualBody ?? fixture.EncodedBody;

            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [DeviceTrustApi.AccessProofHeader] = fixture.ProofPayload,
                [DeviceTrustApi.AccessSignatureHeader] = fixture.Signature,
            };
            if (additionalHeaders is not null)
            {
                foreach (var header in additionalHeaders)
                {
                    headers[header.Key] = header.Value;
                }
            }

            return _api.SendAsync(method, path, body, fixture.BearerToken, headers, cancellationToken);
        }

        /// <summary>The header carrying the base64url step-up proof JSON.</summary>
        public const string StepUpProofHeader = "X-Step-Up-Proof";

        /// <summary>The header carrying the base64url DER step-up signature.</summary>
        public const string StepUpSignatureHeader = "X-Step-Up-Signature";

        /// <summary>The step-up proof version this SDK emits; the server refuses any other.</summary>
        public const int StepUpProofVersion = 2;

        /// <summary>
        /// Serialises a step-up proof v2: the approval of one complete request.
        /// </summary>
        /// <param name="installationId">The canonical installation id.</param>
        /// <param name="accessTokenSha256Hex">Lowercase hex SHA-256 of the bearer token string.</param>
        /// <param name="method">The HTTP method, upper-case.</param>
        /// <param name="path">The path exactly as the access proof names it.</param>
        /// <param name="query">The raw query string as sent, without <c>?</c>; empty when none.</param>
        /// <param name="bodySha256Hex">Lowercase hex SHA-256 of the same body bytes the access proof hashes.</param>
        /// <param name="factor">The factor the key was registered with; must also match the policy.</param>
        /// <param name="nonce">The access proof's nonce.</param>
        /// <param name="timestamp">Unix seconds.</param>
        public static byte[] BuildStepUpProof(
            string installationId,
            string accessTokenSha256Hex,
            string method,
            string path,
            string query,
            string bodySha256Hex,
            string factor,
            string nonce,
            long timestamp)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteNumber("version", StepUpProofVersion);
                writer.WriteString("purpose", "stepup");
                writer.WriteString("installation_id", installationId);
                writer.WriteString("access_token_sha256", accessTokenSha256Hex);
                writer.WriteString("method", method);
                writer.WriteString("path", path);
                writer.WriteString("query", query ?? string.Empty);
                writer.WriteString("body_sha256", bodySha256Hex);
                writer.WriteString("factor", factor);
                writer.WriteString("nonce", nonce);
                writer.WriteNumber("timestamp", timestamp);
                writer.WriteEndObject();
            }

            return buffer.ToArray();
        }

        /// <summary>
        /// The request as both proofs describe it: upper-case method, the body
        /// bytes that will be sent (none for GET), and the signed path and query.
        /// </summary>
        private RequestTarget DescribeRequest(string method, string path, byte[]? body)
        {
            if (string.IsNullOrEmpty(method))
            {
                throw new ArgumentException("An HTTP method is required.", nameof(method));
            }

            var normalizedMethod = method.ToUpperInvariant();
            var (signedPath, query) = _api.ResolveSignedTarget(path);
            return new RequestTarget(
                normalizedMethod,
                signedPath,
                query,
                normalizedMethod == "GET" ? Array.Empty<byte>() : body ?? Array.Empty<byte>());
        }

        private sealed class RequestTarget
        {
            public RequestTarget(string method, string signedPath, string query, byte[] body)
            {
                Method = method;
                SignedPath = signedPath;
                Query = query;
                Body = body;
            }

            public string Method { get; }

            public string SignedPath { get; }

            public string Query { get; }

            public byte[] Body { get; }
        }

        /// <summary>Builds a fresh proof and sends the request it describes.</summary>
        public async Task<JsonElement> SendProtectedAsync(
            string method,
            string path,
            byte[]? body,
            string bearerToken,
            string? proofInstallationId = null,
            CancellationToken cancellationToken = default)
        {
            var fixture = await BuildAccessProofFixtureAsync(
                method,
                path,
                body,
                bearerToken,
                proofInstallationId,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return await SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>Signs a base64url payload the server issued, returning a base64url DER signature.</summary>
        public async Task<string> SignBase64UrlPayloadAsync(
            string payloadBase64Url,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(payloadBase64Url))
            {
                throw new ArgumentException("A payload is required.", nameof(payloadBase64Url));
            }

            var payload = Base64Url.Decode(payloadBase64Url);
            var signature = await _keyStore.SignAsync(payload, cancellationToken).ConfigureAwait(false);
            return Base64Url.Encode(signature);
        }

        /// <summary>Restores a session that was persisted by a previous run.</summary>
        public async Task<AccountSession?> RestoreSessionAsync(CancellationToken cancellationToken = default)
        {
            var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(state.AccessToken)
                || string.IsNullOrEmpty(state.RefreshToken)
                || string.IsNullOrEmpty(state.AccountId))
            {
                return null;
            }

            Session = new AccountSession(state.AccountId!, state.AccessToken!, state.RefreshToken!, null);
            return Session;
        }

        /// <summary>Forgets the local account tokens, leaving the installation identity intact.</summary>
        public async Task ClearSessionAsync(CancellationToken cancellationToken = default)
        {
            Session = null;
            var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            state.AccessToken = null;
            state.RefreshToken = null;
            state.AccountId = null;
            await _stateStore.SaveAsync(state, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Deletes the installation key and all local state, so the next run
        /// enrols as a brand-new installation.
        /// </summary>
        public async Task ResetInstallationAsync(CancellationToken cancellationToken = default)
        {
            await _keyStore.DeleteKeyAsync(cancellationToken).ConfigureAwait(false);
            await DeleteStepUpKeyQuietlyAsync(cancellationToken).ConfigureAwait(false);
            await _stateStore.ClearAsync(cancellationToken).ConfigureAwait(false);
            _identity = null;
            Registration = null;
            StepUpKey = null;
            StepUpUnavailable = null;
            BoundStepUpThumbprint = null;
            Session = null;
            DeviceToken = null;
            DeviceRecord = null;
            LatestIntegrity = null;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            _api.Dispose();
            _identityGate.Dispose();
        }

        private static byte[] BuildIntegrityReport(
            IntegrityChallenge challenge,
            IntegrityCollection collection,
            string installationId)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("challenge_id", challenge.ChallengeId);
                writer.WriteString("challenge_nonce", challenge.Nonce);
                writer.WriteString("installation_id", installationId);
                writer.WriteString("platform", collection.Platform);
                writer.WriteNumber("collector_version", collection.CollectorVersion);
                writer.WriteNumber("collected_at", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                writer.WritePropertyName("probe_results");
                ProbeJsonWriter.WriteProbes(writer, collection.Probes);
                writer.WriteNumber("version", 1);
                writer.WriteEndObject();
            }

            return buffer.ToArray();
        }

        private async Task<AccountSession> OpenAccountAsync(
            string path,
            string handle,
            string password,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(handle))
            {
                throw new ArgumentException("A handle is required.", nameof(handle));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("A password is required.", nameof(password));
            }

            // Account endpoints require a device-role token specifically, not an
            // account one, so a fresh possession proof is taken every time.
            var deviceToken = await AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            if (_integrityCollector is not null)
            {
                await SubmitIntegrityReportAsync(deviceToken, cancellationToken).ConfigureAwait(false);
            }

            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["handle"] = handle,
                ["password"] = password,
            });

            var response = await SendProtectedAsync("POST", path, body, deviceToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var session = AccountSession.Parse(response);
            await AdoptSessionAsync(session, cancellationToken).ConfigureAwait(false);
            return session;
        }

        private async Task AdoptSessionAsync(AccountSession session, CancellationToken cancellationToken)
        {
            Session = session;
            var state = await _stateStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            state.AccountId = session.AccountId;
            state.AccessToken = session.AccessToken;
            state.RefreshToken = session.RefreshToken;
            await _stateStore.SaveAsync(state, cancellationToken).ConfigureAwait(false);
        }

        private async Task<byte[]> SignWithStepUpKeyAsync(byte[] data, string reason, CancellationToken cancellationToken)
        {
            if (_stepUpKeyStore is null)
            {
                throw StepUpKeyMissing();
            }

            try
            {
                return await _stepUpKeyStore.SignAsync(data, reason, cancellationToken).ConfigureAwait(false);
            }
            catch (InstallationKeyException error) when (error.Code == StepUpErrorCodes.KeyInvalidated)
            {
                // The store has already discarded the dead key; stop offering it.
                StepUpKey = null;
                StepUpUnavailable = error;
                throw;
            }
        }

        private InstallationKeyException StepUpKeyMissing()
        {
            return StepUpUnavailable ?? new InstallationKeyException(
                StepUpErrorCodes.KeyNotFound,
                "No step-up key is available on this device. Register the installation first.");
        }

        private async Task DeleteStepUpKeyQuietlyAsync(CancellationToken cancellationToken)
        {
            if (_stepUpKeyStore is null)
            {
                return;
            }

            try
            {
                await _stepUpKeyStore.DeleteKeyAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (InstallationKeyException)
            {
                // A step-up key that cannot be deleted must not stop the
                // installation identity from rotating. The next registration
                // reports it as not matching, and re-enrolment replaces it.
            }

            StepUpKey = null;
        }

        private AccountSession RequireSession()
        {
            return Session ?? throw new DeviceTrustException(
                "No account session is open. Register or log in first.",
                "account_session_required");
        }
    }
}
