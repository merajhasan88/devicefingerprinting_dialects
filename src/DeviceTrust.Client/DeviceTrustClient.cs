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
        public DeviceTrustClient(
            DeviceTrustOptions options,
            IInstallationKeyStore keyStore,
            IInstallationStateStore? stateStore = null,
            IIntegrityProbeCollector? integrityCollector = null,
            HttpClient? httpClient = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
            _stateStore = stateStore ?? new InMemoryInstallationStateStore();
            _integrityCollector = integrityCollector;
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

            RegistrationState registration;
            try
            {
                registration = await _api.RegisterInstallationAsync(
                    identity.InstallationId,
                    Platform,
                    identity.Key.PublicKey,
                    reinstallHint,
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
        /// <param name="path">The API path to name in the proof.</param>
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
            var normalizedMethod = method.ToUpperInvariant();
            var encodedBody = normalizedMethod == "GET" ? Array.Empty<byte>() : body ?? Array.Empty<byte>();

            var proofBytes = AccessProof.Serialize(
                Hex.Sha256Hex(bearerToken),
                AccessProof.BodyHash(encodedBody),
                proofInstallationId ?? identity.InstallationId,
                normalizedMethod,
                nonce ?? AccessProof.CreateNonce(),
                _api.ResolveSignedPath(path),
                timestampSeconds ?? AccessProof.CurrentTimestamp());

            var signature = await _keyStore.SignAsync(proofBytes, cancellationToken).ConfigureAwait(false);

            using var document = JsonDocument.Parse(proofBytes);
            return new AccessProofFixture(
                bearerToken,
                normalizedMethod,
                path,
                encodedBody,
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
            CancellationToken cancellationToken = default)
        {
            if (fixture is null)
            {
                throw new ArgumentNullException(nameof(fixture));
            }

            var method = (actualMethod ?? fixture.SignedMethod).ToUpperInvariant();
            var path = actualPath ?? fixture.SignedPath;
            var body = method == "GET" ? null : actualBody ?? fixture.EncodedBody;

            return _api.SendAsync(
                method,
                path,
                body,
                fixture.BearerToken,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [DeviceTrustApi.AccessProofHeader] = fixture.ProofPayload,
                    [DeviceTrustApi.AccessSignatureHeader] = fixture.Signature,
                },
                cancellationToken);
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
            await _stateStore.ClearAsync(cancellationToken).ConfigureAwait(false);
            _identity = null;
            Registration = null;
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

        private AccountSession RequireSession()
        {
            return Session ?? throw new DeviceTrustException(
                "No account session is open. Register or log in first.",
                "account_session_required");
        }
    }
}
