using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Protocol;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>
    /// The standard battery from DESIGN.md 25.11, run between two simulated
    /// devices instead of two handsets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The battery's shape is fixed so runs are comparable: clean baseline,
    /// account through the enforce gate, stolen access token, stolen refresh
    /// token, the four access-proof boundary tests within ten minutes of a
    /// refresh, and the device-memory check.
    /// </para>
    /// <para>
    /// <b>What this run does not cover.</b> Two things in the handset battery
    /// have no desktop equivalent and are reported as NOT RUN rather than
    /// quietly omitted. The Frida Gadget step needs a real instrumented APK on
    /// real hardware. And the cross-device tests here use two <i>software</i>
    /// keys, so they prove the server refuses a token presented with the wrong
    /// installation key — the protocol property — while proving nothing about
    /// key non-exportability, which is the hardware property. Both still need
    /// phones.
    /// </para>
    /// </remarks>
    public sealed class AccessProofBattery
    {
        private readonly HarnessContext _context;
        private readonly string _integrityMode;

        /// <summary>Creates the battery.</summary>
        public AccessProofBattery(HarnessContext context, string integrityMode)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _integrityMode = integrityMode ?? "observe";
        }

        /// <summary>Runs the battery and returns a process exit code.</summary>
        public async Task<int> RunAsync(CancellationToken cancellationToken)
        {
            var collectorA = new ConformanceProbeCollector();
            var deviceA = _context.CreateEphemeralDevice("device-a", collectorA);
            var deviceB = _context.CreateEphemeralDevice("device-b");

            var results = new List<(string Name, string Status, string Detail)>();

            Report.Heading("0. Clean baseline");
            var registration = await deviceA.RegisterInstallationAsync(
                new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                cancellationToken).ConfigureAwait(false);
            var deviceToken = await deviceA.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            var baseline = await deviceA.SubmitIntegrityReportAsync(deviceToken, cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Installation", registration.InstallationId);
            Report.Field("Device", registration.DeviceId);
            Report.Field("Recognition", registration.Method + " / " + registration.Confidence);
            Report.Field("Integrity score", baseline.Score.ToString(CultureInfo.InvariantCulture) + "/100");
            Report.Field("Integrity verdict", baseline.Verdict);
            Report.Field("Integrity mode", baseline.Mode);
            results.Add((
                "0. Clean baseline scan",
                baseline.Verdict == "trusted" ? "PASS" : "FAIL",
                "score=" + baseline.Score.ToString(CultureInfo.InvariantCulture) + " verdict=" + baseline.Verdict));

            Report.Heading("1. Account through the integrity gate");
            var handle = NewHandle();
            var session = await deviceA.RegisterAccountAsync(handle, "Passw0rd123", cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Handle", handle);
            Report.Field("Account", session.AccountId);
            Report.Field("Server integrity mode", _integrityMode);
            results.Add((
                "1. Account created through the " + _integrityMode + " gate",
                "PASS",
                "POST /v1/accounts/register -> 201"));

            Report.Heading("2. Stolen access token replayed from another installation");
            results.Add(await StolenAccessTokenAsync(deviceA, deviceB, session, cancellationToken)
                .ConfigureAwait(false));

            Report.Heading("3. Stolen refresh token replayed from another installation");
            results.Add(await StolenRefreshTokenAsync(deviceB, session, cancellationToken).ConfigureAwait(false));

            Report.Heading("4. Access-proof boundary tests, within 10 minutes of a refresh");
            var refreshed = await deviceA.RefreshAccountSessionAsync(cancellationToken).ConfigureAwait(false);
            Report.Field("Refreshed at", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            Report.Field("Access token age", "0 s (freshly rotated)");
            results.Add(await ReplayAsync(deviceA, refreshed, cancellationToken).ConfigureAwait(false));
            results.Add(await BodyTamperAsync(deviceA, refreshed, cancellationToken).ConfigureAwait(false));
            results.Add(await PathAndMethodTamperAsync(deviceA, refreshed, cancellationToken).ConfigureAwait(false));
            results.Add(await StaleTimestampAsync(deviceA, refreshed, cancellationToken).ConfigureAwait(false));

            Report.Heading("5. Device memory: a reinstall does not clear a block");
            results.Add(await DeviceMemoryAsync(cancellationToken).ConfigureAwait(false));

            Report.Heading("6. Frida Gadget on real hardware");
            Report.Line("NOT RUN. This step needs a release APK with an embedded gadget on a physical");
            Report.Line("handset. A desktop harness cannot produce the measurement, and fabricating one");
            Report.Line("would test the fixture rather than the detector.");
            results.Add(("6. Frida Gadget compromise", "NOT RUN", "requires physical hardware"));

            Report.Heading("Battery summary");
            foreach (var result in results)
            {
                Report.Outcome(result.Status, result.Name, result.Detail);
            }

            var failed = results.Count(r => r.Status == "FAIL");
            var notRun = results.Count(r => r.Status == "NOT RUN");
            Report.Tally(results.Count - failed - notRun, failed, notRun);

            Report.Line("Cross-device checks used two software keys, so they establish the protocol");
            Report.Line("binding only. Key non-exportability still requires the handset battery.");

            return failed == 0 ? 0 : 1;
        }

        private static string NewHandle()
        {
            var bytes = new byte[4];
            RandomNumberGenerator.Fill(bytes);
            return "battery-" + Hex.Encode(bytes);
        }

        private static (string, string, string) Judge(
            string name,
            DeviceTrustApiException failure,
            int expectedStatus,
            string expectedCode)
        {
            var actual = "HTTP " + failure.StatusCode.ToString(CultureInfo.InvariantCulture)
                         + " " + (failure.Code ?? "<no code>");
            var passed = failure.StatusCode == expectedStatus && failure.Code == expectedCode;
            Report.Field("Result", actual);
            return (
                name,
                passed ? "PASS" : "FAIL",
                passed
                    ? actual
                    : "expected HTTP " + expectedStatus.ToString(CultureInfo.InvariantCulture)
                      + " " + expectedCode + ", got " + actual);
        }

        private async Task<(string, string, string)> StolenAccessTokenAsync(
            DeviceTrustClient victim,
            DeviceTrustClient thief,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            var victimIdentity = await victim.LoadIdentityAsync(cancellationToken).ConfigureAwait(false);

            // The thief claims the victim's installation id inside the proof and
            // signs with its own key. Using the thief's own id instead would fail
            // earlier, on an id mismatch, and would never exercise the signature
            // check that is the actual defence.
            var fixture = await thief.BuildAccessProofFixtureAsync(
                "GET",
                "/v1/account/me",
                null,
                session.AccessToken,
                proofInstallationId: victimIdentity.InstallationId,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            Report.Field("Stolen token installation", victimIdentity.InstallationId);
            Report.Field("Signing key", "the thief's own installation key");

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => thief.SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken),
                "a stolen access token replayed with another key").ConfigureAwait(false);

            return Judge("2. Stolen access token", failure, 401, "invalid_installation_signature");
        }

        private async Task<(string, string, string)> StolenRefreshTokenAsync(
            DeviceTrustClient thief,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            await thief.RegisterInstallationAsync(
                new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest()),
                cancellationToken).ConfigureAwait(false);

            var challenge = await thief.Api.RefreshChallengeAsync(session.RefreshToken, cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Refresh challenge", "HTTP 200 (the stolen token is genuine)");

            var payload = Json.RequireString(challenge, "payload");
            var challengeId = Json.RequireString(challenge, "challenge_id");
            var signature = await thief.SignBase64UrlPayloadAsync(payload, cancellationToken).ConfigureAwait(false);

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => thief.Api.RefreshAsync(session.RefreshToken, challengeId, payload, signature, cancellationToken),
                "a stolen refresh token exchanged with another key").ConfigureAwait(false);

            return Judge("3. Stolen refresh token", failure, 401, "invalid_installation_signature");
        }

        private async Task<(string, string, string)> ReplayAsync(
            DeviceTrustClient device,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["probe_id"] = Guid.NewGuid().ToString(),
                ["message"] = "replay protection test",
            });

            var fixture = await device.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", body, session.AccessToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var first = await device.SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            Report.Field("First request", Json.GetString(first, "access_proof") == "accepted" ? "HTTP 200 accepted" : "unexpected");

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken),
                "a byte-identical replay").ConfigureAwait(false);

            return Judge("4a. Exact signed-request replay", failure, 401, "access_proof_replay");
        }

        private async Task<(string, string, string)> BodyTamperAsync(
            DeviceTrustClient device,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            var signed = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["message"] = "ORIGINAL body signed by the installation key",
            });
            var tampered = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["message"] = "TAMPERED after the proof was signed",
            });

            var fixture = await device.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", signed, session.AccessToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendAccessProofFixtureAsync(fixture, actualBody: tampered, cancellationToken: cancellationToken),
                "a body changed after signing").ConfigureAwait(false);

            return Judge("4b. Request-body tampering", failure, 401, "access_proof_body_mismatch");
        }

        private async Task<(string, string, string)> PathAndMethodTamperAsync(
            DeviceTrustClient device,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            var pathFixture = await device.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/not-the-requested-route", null, session.AccessToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var pathFailure = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendAccessProofFixtureAsync(
                    pathFixture, actualMethod: "GET", actualPath: "/v1/account/me", cancellationToken: cancellationToken),
                "a proof naming another path").ConfigureAwait(false);

            var methodFixture = await device.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/protected-echo", null, session.AccessToken,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var methodFailure = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendAccessProofFixtureAsync(
                    methodFixture,
                    actualMethod: "POST",
                    actualPath: "/v1/account/protected-echo",
                    actualBody: Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["message"] = "actual POST while the proof says GET",
                    }),
                    cancellationToken: cancellationToken),
                "a proof naming another method").ConfigureAwait(false);

            var pathOk = pathFailure.StatusCode == 401 && pathFailure.Code == "access_proof_path_mismatch";
            var methodOk = methodFailure.StatusCode == 401 && methodFailure.Code == "access_proof_method_mismatch";
            var detail = "path: HTTP " + pathFailure.StatusCode.ToString(CultureInfo.InvariantCulture) + " "
                         + (pathFailure.Code ?? "<no code>") + "; method: HTTP "
                         + methodFailure.StatusCode.ToString(CultureInfo.InvariantCulture) + " "
                         + (methodFailure.Code ?? "<no code>");
            Report.Field("Result", detail);

            return ("4c. HTTP path and method binding", pathOk && methodOk ? "PASS" : "FAIL", detail);
        }

        private async Task<(string, string, string)> StaleTimestampAsync(
            DeviceTrustClient device,
            AccountSession session,
            CancellationToken cancellationToken)
        {
            // The server allows 120 seconds of skew. 180 is equivalent to
            // replaying a captured proof after expiry, without making the run
            // wait two minutes.
            const int simulatedAgeSeconds = 180;
            var fixture = await device.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/me", null, session.AccessToken,
                timestampSeconds: AccessProof.CurrentTimestamp() - simulatedAgeSeconds,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            Report.Field("Proof age", simulatedAgeSeconds.ToString(CultureInfo.InvariantCulture) + " s (window 120 s)");

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendAccessProofFixtureAsync(fixture, cancellationToken: cancellationToken),
                "a proof outside the timestamp window").ConfigureAwait(false);

            return Judge("4d. Access-proof timestamp window", failure, 401, "access_proof_timestamp_outside_window");
        }

        private async Task<(string, string, string)> DeviceMemoryAsync(CancellationToken cancellationToken)
        {
            if (_integrityMode != "enforce")
            {
                Report.Line("Server is in observe mode, so the gate does not refuse anything. Skipped.");
                return ("5. Device memory across a reinstall", "NOT RUN", "server is in observe mode");
            }

            var hint = new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest());

            var dirty = new ConformanceProbeCollector();
            dirty.WithScenario("frida", probes => probes["runtime_maps"] = ProbeResult.Ok()
                .With("fixture", ConformanceProbeCollector.FixtureLabel)
                .With("suspicious_tokens", new List<string> { "frida" })
                .With("suspicious_line_count", 2));

            var compromised = _context.CreateEphemeralDevice("memory-original", dirty);
            var firstRegistration = await compromised.RegisterInstallationAsync(hint, cancellationToken)
                .ConfigureAwait(false);
            var firstToken = await compromised.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            var blockedDecision = await compromised.SubmitIntegrityReportAsync(firstToken, cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Compromised scan", blockedDecision.Verdict + " (" + blockedDecision.Score.ToString(CultureInfo.InvariantCulture) + ")");

            var reinstalled = _context.CreateEphemeralDevice("memory-reinstall");
            var secondRegistration = await reinstalled.RegisterInstallationAsync(hint, cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Reinstall correlated", secondRegistration.DeviceId == firstRegistration.DeviceId ? "yes, same device" : "no");
            var secondToken = await reinstalled.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            var cleanDecision = await reinstalled.SubmitIntegrityReportAsync(secondToken, cancellationToken)
                .ConfigureAwait(false);
            Report.Field("Reinstall's own scan", cleanDecision.Verdict);

            var failure = await HarnessContext.ExpectApiFailureAsync(
                () => reinstalled.RegisterAccountAsync(NewHandle(), "Passw0rd123", cancellationToken),
                "an account operation after reinstalling on a blocked device").ConfigureAwait(false);

            return Judge("5. Device memory across a reinstall", failure, 403, "integrity_device_blocked_recently");
        }
    }
}
