using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Protocol;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>
    /// Proves that this .NET client produces proofs the server accepts, and that
    /// each of its boundary cases is rejected with the right code.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Python <c>conformance_suite.py</c> already proves the server side and
    /// is client-agnostic, so it is not reimplemented here for its own sake. What
    /// only a .NET harness can establish is that the .NET SDK's bytes are
    /// acceptable: DER signatures rather than IEEE P-1363, the RFC 7638
    /// thumbprint computed identically, an access proof whose body hash matches
    /// the bytes <see cref="System.Net.Http.HttpClient"/> actually transmits, and
    /// the nested error envelope parsed correctly.
    /// </para>
    /// <para>
    /// Every check that expects a rejection asserts the exact server code. A test
    /// that merely asserted "this failed" would pass just as happily if the
    /// request failed for an unrelated reason, which is the usual way a security
    /// test quietly stops testing anything.
    /// </para>
    /// </remarks>
    public sealed class ClientConformanceSuite
    {
        private readonly HarnessContext _context;
        private readonly string _integrityMode;

        private DeviceTrustClient? _device;
        private ConformanceProbeCollector? _collector;
        private DeviceTrustClient? _scoringDevice;
        private ConformanceProbeCollector? _scoringCollector;
        private string? _deviceToken;
        private AccountSession? _session;
        private string? _rotatedAwayRefreshToken;

        /// <summary>Creates the suite.</summary>
        public ClientConformanceSuite(HarnessContext context, string integrityMode)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _integrityMode = integrityMode ?? "observe";
        }

        /// <summary>Runs every check and returns a process exit code.</summary>
        public Task<int> RunAsync(CancellationToken cancellationToken)
        {
            var runner = new CheckRunner();

            runner.Add("config: a client with no endpoint fails api_base_url_missing", _ =>
            {
                var options = new DeviceTrustOptions { BaseUrl = null, Platform = "android" };
                try
                {
                    options.ResolveBaseUri();
                }
                catch (DeviceTrustConfigurationException error)
                {
                    CheckRunner.Expect(
                        error.Code == "api_base_url_missing",
                        "expected api_base_url_missing, got " + error.Code);
                    return Task.CompletedTask;
                }

                throw new CheckFailedException("a client with no endpoint was allowed to resolve one");
            });

            runner.Add("crypto: the client signs ASN.1 DER, not IEEE P-1363", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var payload = Base64Url.Encode(Encoding.UTF8.GetBytes("device-trust dotnet signature shape probe"));
                var signature = Base64Url.Decode(
                    await device.SignBase64UrlPayloadAsync(payload, token).ConfigureAwait(false));

                CheckRunner.Expect(
                    EcdsaSignatureFormat.LooksLikeDerSequence(signature),
                    "the signature is not a DER SEQUENCE. .NET's default ECDsa.SignData overload emits "
                    + "IEEE P-1363 r||s, which this server rejects on every call as "
                    + "invalid_installation_signature. Use the DSASignatureFormat.Rfc3279DerSequence overload.");

                CheckRunner.Expect(
                    signature.Length != 64 || signature[0] == 0x30,
                    "a bare 64-byte signature is P-1363, not DER");
            });

            runner.Add("identity: a new key enrols as a new installation", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var registration = await device.RegisterInstallationAsync(
                    new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    !string.IsNullOrEmpty(registration.DeviceId),
                    "the server returned no device_id");
            });

            runner.Add("identity: the client's RFC 7638 thumbprint matches the server's", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);

                CheckRunner.Expect(
                    string.Equals(identity.KeyThumbprint, device.Registration!.KeyThumbprint, StringComparison.Ordinal),
                    "client thumbprint " + identity.KeyThumbprint + " != server thumbprint "
                    + device.Registration.KeyThumbprint);
            });

            runner.Add("identity: the key thumbprint, not the UUID, is authoritative", async token =>
            {
                // Re-register the same key under a fresh UUID. The server must
                // answer with the original installation and exact_key recognition.
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);
                var original = device.Registration!;

                var response = await device.Api.RegisterInstallationAsync(
                    Guid.NewGuid().ToString(),
                    device.Platform,
                    identity.Key.PublicKey,
                    null,
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    string.Equals(response.InstallationId, original.InstallationId, StringComparison.Ordinal),
                    "the server issued a different installation for the same key");
                CheckRunner.Expect(
                    response.Method == "exact_key",
                    "expected exact_key recognition, got " + response.Method);
            });

            runner.Add("possession: a signed challenge yields a device token", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                _deviceToken = await device.AcquireDeviceTokenAsync(token).ConfigureAwait(false);
                var claims = JwtClaims(_deviceToken);

                CheckRunner.Expect(
                    Json.GetString(claims, "role") == "device",
                    "expected role=device in the issued token");
            });

            runner.Add("integrity: a pristine fixture scores zero and is trusted", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var decision = await device.SubmitIntegrityReportAsync(
                    await FreshDeviceTokenAsync(device, token).ConfigureAwait(false),
                    token).ConfigureAwait(false);

                if (decision.Reasons.Any(reason => reason.Code == "android_signing_certificate_mismatch"))
                {
                    throw new SkipCheckException(
                        "the server does not trust this harness's certificate; start it with "
                        + "INTEGRITY_ANDROID_CERT_SHA256="
                        + ConformanceProbeCollector.ConformanceCertificateSha256 + " (or empty)");
                }

                CheckRunner.Expect(
                    decision.Verdict == "trusted",
                    "expected trusted, got " + decision.Verdict + " ("
                    + Report.Join(decision.Reasons.Select(r => r.Code).ToList()) + ")");
                CheckRunner.Expect(decision.Score == 0, "expected score 0, got " + decision.Score);
            });

            runner.Add("integrity: Frida mapped into the process blocks", async token =>
            {
                var decision = await WithScenarioAsync(
                    "frida_runtime",
                    probes => probes["runtime_maps"] = ProbeResult.Ok()
                        .With("fixture", ConformanceProbeCollector.FixtureLabel)
                        .With("suspicious_tokens", new List<string> { "frida", "gadget" })
                        .With("suspicious_line_count", 3),
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    decision.Reasons.Any(reason => reason.Code == "android_frida_runtime_artifact"),
                    "expected android_frida_runtime_artifact, got "
                    + Report.Join(decision.Reasons.Select(r => r.Code).ToList()));
                CheckRunner.Expect(decision.Verdict == "block", "expected block, got " + decision.Verdict);
            });

            runner.Add("integrity: a renamed gadget is still caught by its runtime thread", async token =>
            {
                // runtime_maps and frida_ports stay clean, as they are when the
                // injected library is renamed and moved off the default port. The
                // structural thread signal must still block, or the rename
                // evasion recorded in DESIGN.md 27.11 is back.
                var decision = await WithScenarioAsync(
                    "renamed_gadget",
                    probes => probes["instrumentation_threads"] = ProbeResult.Ok()
                        .With("fixture", ConformanceProbeCollector.FixtureLabel)
                        .With("frida_threads", new List<string> { "gum-js-loop" })
                        .With("glib_threads", new List<string>())
                        .With("token_threads", new List<string>())
                        .With("thread_count", 44),
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    decision.Reasons.Any(reason => reason.Code == "android_instrumentation_runtime_thread"),
                    "expected android_instrumentation_runtime_thread, got "
                    + Report.Join(decision.Reasons.Select(r => r.Code).ToList()));
                CheckRunner.Expect(decision.Verdict == "block", "a renamed gadget must still block");
            });

            runner.Add("integrity: a probe that fails to run is penalised", async token =>
            {
                var decision = await WithScenarioAsync(
                    "broken_probe",
                    probes => probes["mounts"] = ProbeResult.Error("IOException", "permission denied"),
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    decision.Reasons.Any(reason => reason.Code.StartsWith("integrity_probe_failed", StringComparison.Ordinal)),
                    "expected an integrity_probe_failed reason, got "
                    + Report.Join(decision.Reasons.Select(r => r.Code).ToList()));
            });

            runner.Add("account: a device token opens an account", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                _session = await device.RegisterAccountAsync(NewHandle(), "Passw0rd123", token)
                    .ConfigureAwait(false);

                CheckRunner.Expect(
                    !string.IsNullOrEmpty(_session.AccessToken) && !string.IsNullOrEmpty(_session.RefreshToken),
                    "the server issued no token pair");
            });

            runner.Add("access proof: a correctly signed request is accepted", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var response = await device.ProtectedEchoAsync(
                    new Dictionary<string, object?>(StringComparer.Ordinal) { ["hello"] = "conformance" },
                    token).ConfigureAwait(false);

                CheckRunner.Expect(
                    Json.GetString(response, "access_proof") == "accepted",
                    "the server did not report an accepted access proof");
            });

            runner.Add("access proof: an exact replay is rejected", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var body = Json.SerializeToUtf8Bytes(
                    new Dictionary<string, object?>(StringComparer.Ordinal) { ["replay"] = true });
                var fixture = await device.BuildAccessProofFixtureAsync(
                    "POST", "/v1/account/protected-echo", body, _session!.AccessToken,
                    cancellationToken: token).ConfigureAwait(false);

                var first = await device.SendAccessProofFixtureAsync(fixture, cancellationToken: token)
                    .ConfigureAwait(false);
                CheckRunner.Expect(
                    Json.GetString(first, "access_proof") == "accepted",
                    "the control request was not accepted");

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.SendAccessProofFixtureAsync(fixture, cancellationToken: token),
                    "a byte-identical replay of a signed proof").ConfigureAwait(false);

                ExpectRejection(failure, 401, "access_proof_replay");
            });

            runner.Add("access proof: a tampered body is rejected", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var signedBody = Json.SerializeToUtf8Bytes(
                    new Dictionary<string, object?>(StringComparer.Ordinal) { ["amount"] = 1 });
                var tamperedBody = Json.SerializeToUtf8Bytes(
                    new Dictionary<string, object?>(StringComparer.Ordinal) { ["amount"] = 1000000 });

                var fixture = await device.BuildAccessProofFixtureAsync(
                    "POST", "/v1/account/protected-echo", signedBody, _session!.AccessToken,
                    cancellationToken: token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.SendAccessProofFixtureAsync(fixture, actualBody: tamperedBody, cancellationToken: token),
                    "a body changed after the proof was signed").ConfigureAwait(false);

                ExpectRejection(failure, 401, "access_proof_body_mismatch");
            });

            runner.Add("access proof: a tampered path is rejected", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var fixture = await device.BuildAccessProofFixtureAsync(
                    "GET", "/v1/account/not-the-requested-route", null, _session!.AccessToken,
                    cancellationToken: token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.SendAccessProofFixtureAsync(
                        fixture, actualMethod: "GET", actualPath: "/v1/account/me", cancellationToken: token),
                    "a proof naming a different path").ConfigureAwait(false);

                ExpectRejection(failure, 401, "access_proof_path_mismatch");
            });

            runner.Add("access proof: a tampered method is rejected", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var fixture = await device.BuildAccessProofFixtureAsync(
                    "GET", "/v1/account/protected-echo", null, _session!.AccessToken,
                    cancellationToken: token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.SendAccessProofFixtureAsync(
                        fixture,
                        actualMethod: "POST",
                        actualPath: "/v1/account/protected-echo",
                        actualBody: Json.SerializeToUtf8Bytes(
                            new Dictionary<string, object?>(StringComparer.Ordinal)
                            {
                                ["message"] = "actual POST while the proof says GET",
                            }),
                        cancellationToken: token),
                    "a proof naming a different method").ConfigureAwait(false);

                ExpectRejection(failure, 401, "access_proof_method_mismatch");
            });

            runner.Add("access proof: a stale timestamp is rejected", async token =>
            {
                // The server allows 120 seconds of skew. 3600 is unambiguous and
                // does not make the run sit idle waiting for a window to close.
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var fixture = await device.BuildAccessProofFixtureAsync(
                    "GET", "/v1/account/me", null, _session!.AccessToken,
                    timestampSeconds: AccessProof.CurrentTimestamp() - 3600,
                    cancellationToken: token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.SendAccessProofFixtureAsync(fixture, cancellationToken: token),
                    "a proof timestamped an hour ago").ConfigureAwait(false);

                ExpectRejection(failure, 401, "access_proof_timestamp_outside_window");
            });

            runner.Add("access proof: a proof signed by another installation is rejected", async token =>
            {
                // A structurally perfect proof, naming this installation, signed
                // by a different key: the shape of a stolen access token replayed
                // from another device.
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);

                var attacker = _context.CreateEphemeralDevice("attacker");
                var fixture = await attacker.BuildAccessProofFixtureAsync(
                    "GET", "/v1/account/me", null, _session!.AccessToken,
                    proofInstallationId: identity.InstallationId,
                    cancellationToken: token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => attacker.SendAccessProofFixtureAsync(fixture, cancellationToken: token),
                    "a proof signed by a different installation key").ConfigureAwait(false);

                ExpectRejection(failure, 401, "invalid_installation_signature");
            });

            runner.Add("errors: the nested error envelope is parsed", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => device.Api.CreateInstallationChallengeAsync(Guid.NewGuid().ToString(), token),
                    "a challenge for an unregistered installation").ConfigureAwait(false);

                CheckRunner.Expect(
                    failure.Code == "installation_not_found",
                    "expected the code from error.code, got " + (failure.Code ?? "<null>")
                    + ". A client reading a flat top-level 'code' sees null here.");
                CheckRunner.Expect(
                    !string.IsNullOrEmpty(failure.Message),
                    "the message from error.message was not parsed");
            });

            runner.Add("refresh: rotation issues a new family member", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                _rotatedAwayRefreshToken = _session!.RefreshToken;
                var rotated = await device.RefreshAccountSessionAsync(token).ConfigureAwait(false);
                _session = rotated;

                CheckRunner.Expect(
                    !string.Equals(rotated.RefreshToken, _rotatedAwayRefreshToken, StringComparison.Ordinal),
                    "the server returned the same refresh token");

                var me = await device.GetAccountMeAsync(token).ConfigureAwait(false);
                CheckRunner.Expect(
                    Json.GetString(me, "access_proof") == "accepted",
                    "the newly issued access token was not usable");
            });

            // Order matters here. Reusing a rotated refresh token revokes the
            // entire family, and the current token belongs to that family, so the
            // stolen-token check must run first or it fails with
            // refresh_token_reuse instead of the sender-constraint code it is
            // actually testing.
            runner.Add("refresh: a stolen refresh token fails at the signature, not the token", async token =>
            {
                // The challenge must succeed — that proves the stolen token is
                // genuine — and only the signed exchange may fail. A test where
                // the challenge already failed would prove nothing about
                // sender constraint.
                var attacker = _context.CreateEphemeralDevice("refresh-thief");
                await attacker.RegisterInstallationAsync(
                    new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                    token).ConfigureAwait(false);

                var challenge = await attacker.Api.RefreshChallengeAsync(_session!.RefreshToken, token)
                    .ConfigureAwait(false);
                var payload = Json.RequireString(challenge, "payload");
                var signature = await attacker.SignBase64UrlPayloadAsync(payload, token).ConfigureAwait(false);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => attacker.Api.RefreshAsync(
                        _session.RefreshToken,
                        Json.RequireString(challenge, "challenge_id"),
                        payload,
                        signature,
                        token),
                    "a refresh token from another installation").ConfigureAwait(false);

                ExpectRejection(failure, 401, "invalid_installation_signature");
            });

            runner.Add("refresh: reusing a rotated token revokes the family", async token =>
            {
                var device = await EnsureDeviceAsync(token).ConfigureAwait(false);
                var old = _rotatedAwayRefreshToken!;

                DeviceTrustApiException failure;
                try
                {
                    var challenge = await device.Api.RefreshChallengeAsync(old, token).ConfigureAwait(false);
                    var payload = Json.RequireString(challenge, "payload");
                    var challengeId = Json.RequireString(challenge, "challenge_id");
                    var signature = await device.SignBase64UrlPayloadAsync(payload, token).ConfigureAwait(false);
                    failure = await HarnessContext.ExpectApiFailureAsync(
                        () => device.Api.RefreshAsync(old, challengeId, payload, signature, token),
                        "a rotated refresh token reused").ConfigureAwait(false);
                }
                catch (DeviceTrustApiException error)
                {
                    // The reuse may also be detected at the challenge, before a
                    // signature is ever requested. Either point is legitimate,
                    // and the assertions below hold for both.
                    failure = error;
                }

                CheckRunner.Expect(failure.StatusCode == 401, "expected 401, got " + failure.StatusCode);
                CheckRunner.Expect(
                    failure.Code is "refresh_token_reuse" or "refresh_session_revoked",
                    "expected a reuse/revocation code, got " + (failure.Code ?? "<null>"));
            });

            runner.Add("enforcement: a blocked device cannot reach protected endpoints", async token =>
            {
                if (_integrityMode != "enforce")
                {
                    throw new SkipCheckException("server is in observe mode");
                }

                var collector = new ConformanceProbeCollector();
                collector.WithScenario("frida", probes => probes["runtime_maps"] = ProbeResult.Ok()
                    .With("fixture", ConformanceProbeCollector.FixtureLabel)
                    .With("suspicious_tokens", new List<string> { "frida" })
                    .With("suspicious_line_count", 2));

                var blocked = _context.CreateEphemeralDevice("blocked", collector);
                await blocked.RegisterInstallationAsync(
                    new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                    token).ConfigureAwait(false);
                var deviceToken = await blocked.AcquireDeviceTokenAsync(token).ConfigureAwait(false);
                var decision = await blocked.SubmitIntegrityReportAsync(deviceToken, token).ConfigureAwait(false);
                CheckRunner.Expect(decision.Verdict == "block", "setup failed: expected block, got " + decision.Verdict);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => blocked.RegisterAccountAsync(NewHandle(), "Passw0rd123", token),
                    "an account operation from a blocked device").ConfigureAwait(false);

                ExpectRejection(failure, 403, "integrity_blocked");
            });

            runner.Add("enforcement: reinstalling does not clear a blocked device", async token =>
            {
                if (_integrityMode != "enforce")
                {
                    throw new SkipCheckException("server is in observe mode");
                }

                var hint = new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest());

                var dirty = new ConformanceProbeCollector();
                dirty.WithScenario("frida", probes => probes["runtime_maps"] = ProbeResult.Ok()
                    .With("fixture", ConformanceProbeCollector.FixtureLabel)
                    .With("suspicious_tokens", new List<string> { "frida" })
                    .With("suspicious_line_count", 2));

                var first = _context.CreateEphemeralDevice("blocked-original", dirty);
                var firstRegistration = await first.RegisterInstallationAsync(hint, token).ConfigureAwait(false);
                var firstToken = await first.AcquireDeviceTokenAsync(token).ConfigureAwait(false);
                var decision = await first.SubmitIntegrityReportAsync(firstToken, token).ConfigureAwait(false);
                CheckRunner.Expect(decision.Verdict == "block", "setup failed: expected block, got " + decision.Verdict);

                // A second installation on the same physical device: a new key,
                // a new UUID, a clean scan of its own.
                var reinstalled = _context.CreateEphemeralDevice("blocked-reinstall");
                var secondRegistration = await reinstalled.RegisterInstallationAsync(hint, token).ConfigureAwait(false);
                CheckRunner.Expect(
                    string.Equals(secondRegistration.DeviceId, firstRegistration.DeviceId, StringComparison.Ordinal),
                    "the reinstall did not correlate to the same device");

                var secondToken = await reinstalled.AcquireDeviceTokenAsync(token).ConfigureAwait(false);
                var clean = await reinstalled.SubmitIntegrityReportAsync(secondToken, token).ConfigureAwait(false);
                CheckRunner.Expect(
                    clean.Verdict == "trusted",
                    "the new installation's own scan should be clean, got " + clean.Verdict);

                var failure = await HarnessContext.ExpectApiFailureAsync(
                    () => reinstalled.RegisterAccountAsync(NewHandle(), "Passw0rd123", token),
                    "an account operation after reinstalling on a blocked device").ConfigureAwait(false);

                ExpectRejection(failure, 403, "integrity_device_blocked_recently");
            });

            return runner.RunAsync(cancellationToken);
        }

        private static void ExpectRejection(DeviceTrustApiException failure, int status, string code)
        {
            CheckRunner.Expect(
                failure.StatusCode == status,
                "expected HTTP " + status.ToString(CultureInfo.InvariantCulture) + ", got "
                + failure.StatusCode.ToString(CultureInfo.InvariantCulture)
                + " (" + (failure.Code ?? "<no code>") + ")");
            CheckRunner.Expect(
                failure.Code == code,
                "expected " + code + ", got " + (failure.Code ?? "<no code>"));
        }

        private static string NewHandle()
        {
            var bytes = new byte[4];
            RandomNumberGenerator.Fill(bytes);
            return "dotnet-" + Hex.Encode(bytes);
        }

        private static JsonElement JwtClaims(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new CheckFailedException("the issued token is not a three-part JWT");
            }

            using var document = JsonDocument.Parse(Base64Url.Decode(parts[1]));
            return document.RootElement.Clone();
        }

        private async Task<DeviceTrustClient> EnsureDeviceAsync(CancellationToken cancellationToken)
        {
            if (_device is null)
            {
                _collector = new ConformanceProbeCollector();
                _device = _context.CreateEphemeralDevice("primary", _collector);
                await _device.LoadIdentityAsync(cancellationToken).ConfigureAwait(false);
            }

            return _device;
        }

        /// <summary>
        /// A second installation, used only for the scoring scenarios.
        /// </summary>
        /// <remarks>
        /// The scoring checks deliberately submit reports that score as blocked,
        /// and the server remembers a blocked verdict against the <i>device</i>,
        /// not just the installation, so that reinstalling cannot clear it. Using
        /// the primary installation for those would therefore poison every later
        /// account check with <c>integrity_device_blocked_recently</c> — which is
        /// the gate working correctly, reported as a dozen unrelated failures.
        /// The Python suite separates the two sessions for the same reason.
        /// </remarks>
        private async Task<DeviceTrustClient> EnsureScoringDeviceAsync(CancellationToken cancellationToken)
        {
            if (_scoringDevice is null)
            {
                _scoringCollector = new ConformanceProbeCollector();
                _scoringDevice = _context.CreateEphemeralDevice("scoring", _scoringCollector);
                await _scoringDevice.RegisterInstallationAsync(
                    new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                    cancellationToken).ConfigureAwait(false);
            }

            return _scoringDevice;
        }

        private async Task<string> FreshDeviceTokenAsync(DeviceTrustClient device, CancellationToken cancellationToken)
        {
            _deviceToken = await device.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            return _deviceToken;
        }

        /// <summary>
        /// Submits one altered report from the scoring installation.
        /// </summary>
        /// <remarks>
        /// The scoring device is resolved here rather than passed in. An earlier
        /// version let each check choose, and one of them paired the scoring
        /// collector's mutation with the primary client — so the mutation was
        /// configured on a collector nobody used and the server scored a pristine
        /// report. The check failed with "expected a Frida thread reason, got
        /// none", which looks like a server regression and is not one.
        /// </remarks>
        private async Task<IntegrityDecision> WithScenarioAsync(
            string name,
            Action<Dictionary<string, ProbeResult>> mutation,
            CancellationToken cancellationToken)
        {
            var device = await EnsureScoringDeviceAsync(cancellationToken).ConfigureAwait(false);
            _scoringCollector!.ClearScenarios().WithScenario(name, mutation);
            try
            {
                var deviceToken = await device.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
                return await device.SubmitIntegrityReportAsync(deviceToken, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _scoringCollector.ClearScenarios();
            }
        }
    }
}
