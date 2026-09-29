using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Protocol;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>
    /// The checks added to the reference suite since DESIGN.md 33, driven
    /// through this SDK: key_security, the step-up key, step-up proofs,
    /// re-enrolment, the accounts-per-device bands and parallel clients.
    /// </summary>
    /// <remarks>
    /// Each mirrors the Python check of the same name in
    /// <c>conformance_suite.py</c>. What they add over the Python ones is that the
    /// bytes come from <see cref="DeviceTrustClient"/> — the same code a handset
    /// runs — so a check passing here means this client's step-up proof,
    /// re-enrolment proof and registration block are what the server accepts.
    /// The step-up keys are <see cref="SoftwareStepUpKeyStore"/>: they prove the
    /// wire contract, not that a user was present, which only the handset
    /// battery can.
    /// </remarks>
    public sealed class StepUpConformanceChecks
    {
        private const string SensitivePath = "/v1/account/sensitive-echo";
        private const string Password = "Passw0rd123";

        private readonly HarnessContext _context;

        /// <summary>Creates the check set.</summary>
        public StepUpConformanceChecks(HarnessContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        /// <summary>Adds every check to <paramref name="runner"/>.</summary>
        public void AddTo(CheckRunner runner)
        {
            runner.Add("identity: the client reports key_security and the server records it", CheckKeySecurityAsync);
            runner.Add("step-up: an optional step-up key registers with its reported auth, absent by default",
                CheckStepUpKeyRegistrationAsync);
            runner.Add("step-up: re-registration can never attach or replace a step-up key",
                CheckStepUpKeyImmutableAsync);
            runner.Add("step-up: a sensitive path requires a valid step-up proof", CheckStepUpAsync);
            runner.Add("step-up: re-enrolment needs the password and the new key's own proof",
                CheckStepUpReenrolAsync);
            runner.Add("risk: accounts per device follow the DBA policy (defaults 2 elevated, 3 review, 4 block)",
                CheckDeviceAccountBandsAsync);
            runner.Add("concurrency: parallel clients neither crash nor stall the server [db]",
                CheckParallelClientsAsync);
        }

        private async Task CheckKeySecurityAsync(CancellationToken token)
        {
            var device = _context.CreateEphemeralDevice("key-security");
            var registration = await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            var stored = registration.KeySecurity
                         ?? throw new SkipCheckException("this server predates the key_security block");

            // The harness key is a software file and says so. A client that
            // reported "hardware" here would be lying to the hardware-backing
            // policy, and one that sent nothing would be stored as unknown.
            CheckRunner.Expect(stored.SecurityLevel == "software",
                "security_level round-tripped as " + (stored.SecurityLevel ?? "<null>"));
            CheckRunner.Expect(stored.HardwareBacked == false,
                "hardware_backed round-tripped as " + Describe(stored.HardwareBacked));
            CheckRunner.Expect(stored.Provider == "software-file",
                "provider round-tripped as " + (stored.Provider ?? "<null>"));
        }

        private async Task CheckStepUpKeyRegistrationAsync(CancellationToken token)
        {
            var settings = await SettingsAsync(token).ConfigureAwait(false);
            var policyMode = Setting(settings, "stepup_mode") ?? "per_use";
            var policyWindow = SettingInt(settings, "stepup_window_seconds", 0);

            // The Android 9/10 shape: per-use was asked for, the keystore could
            // only give a 30-second hardware window, and says so.
            var windowed = new StepUpKeyAuth(StepUpKeyAuth.FactorPasscode, StepUpKeyAuth.ModeWindowed, 30);
            var device = _context.CreateEphemeralDevice(
                "stepup-register", stepUpKeyStore: new SoftwareStepUpKeyStore(true, windowed));
            var registration = await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);

            CheckRunner.Expect(registration.StepUpKeyRegistered, "expected stepup_key_registered=true");
            CheckRunner.Expect(windowed.Equals(registration.StepUpKeyAuth),
                "reported auth not echoed: " + (registration.StepUpKeyAuth?.Description ?? "<null>"));
            var want = policyMode == "per_use" || 30 > policyWindow;
            CheckRunner.Expect(registration.StepUpPolicyDowngrade == want,
                "stepup_policy_downgrade expected " + want + " under policy " + policyMode + "/"
                + policyWindow.ToString(CultureInfo.InvariantCulture) + ", got "
                + Describe(registration.StepUpPolicyDowngrade));
            CheckRunner.Expect(device.StepUpUsable, "the client does not consider its bound key usable");

            var plain = _context.CreateEphemeralDevice("stepup-plain");
            var plainRegistration = await plain.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            CheckRunner.Expect(!plainRegistration.StepUpKeyRegistered, "a plain enrol must not register a step-up key");
            CheckRunner.Expect(plainRegistration.StepUpKeyAuth is null, "a plain enrol must report no step-up auth");
            CheckRunner.Expect(plain.StepUpUnavailable?.Code == StepUpErrorCodes.NotConfigured,
                "a client with no step-up store must say why it has no key");
        }

        private async Task CheckStepUpKeyImmutableAsync(CancellationToken token)
        {
            var bound = new SoftwareStepUpKeyStore(true);
            var device = _context.CreateEphemeralDevice("stepup-immutable", stepUpKeyStore: bound);
            var first = await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            CheckRunner.Expect(first.StepUpKeyRegistered, "initial enrol did not bind the step-up key");
            var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);

            using var attackerStore = new SoftwareStepUpKeyStore(
                true, new StepUpKeyAuth(StepUpKeyAuth.FactorPasscode, StepUpKeyAuth.ModeWindowed, 3600));
            var attacker = await attackerStore.GetOrCreateKeyAsync(StepUpKeyAuth.PasscodePerUse, token)
                .ConfigureAwait(false);

            var swapped = await device.Api.RegisterInstallationAsync(
                identity.InstallationId, device.Platform, identity.Key.PublicKey, FreshHint(),
                identity.Key, attacker, token).ConfigureAwait(false);
            CheckRunner.Expect(swapped.StepUpKeyRegistered && swapped.StepUpKeyMatches == false,
                "a different step-up key must not replace the bound one: registered="
                + swapped.StepUpKeyRegistered + " matches=" + Describe(swapped.StepUpKeyMatches));
            CheckRunner.Expect(StepUpKeyAuth.PasscodePerUse.Equals(swapped.StepUpKeyAuth),
                "the bound key's auth must be unchanged, got " + (swapped.StepUpKeyAuth?.Description ?? "<null>"));

            var again = await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            CheckRunner.Expect(again.StepUpKeyMatches == true,
                "the bound step-up key must match on re-registration, got " + Describe(again.StepUpKeyMatches));

            var plain = _context.CreateEphemeralDevice("stepup-immutable-plain");
            await plain.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            var plainIdentity = await plain.LoadIdentityAsync(token).ConfigureAwait(false);
            var attach = await plain.Api.RegisterInstallationAsync(
                plainIdentity.InstallationId, plain.Platform, plainIdentity.Key.PublicKey, FreshHint(),
                plainIdentity.Key, attacker, token).ConfigureAwait(false);
            CheckRunner.Expect(!attach.StepUpKeyRegistered && attach.StepUpKeyMatches == false,
                "re-registration must not attach a step-up key: registered=" + attach.StepUpKeyRegistered
                + " matches=" + Describe(attach.StepUpKeyMatches));
        }

        private async Task CheckStepUpAsync(CancellationToken token)
        {
            var settings = await SettingsAsync(token).ConfigureAwait(false);
            if (!(Setting(settings, "stepup_required_paths") ?? string.Empty).Contains(SensitivePath))
            {
                throw new SkipCheckException("sensitive-echo not in stepup_required_paths; set it to run this check");
            }

            var factor = Setting(settings, "stepup_factor") ?? StepUpKeyAuth.FactorPasscode;
            var keyAuth = new StepUpKeyAuth(factor, StepUpKeyAuth.ModePerUse, 0);
            var store = new SoftwareStepUpKeyStore(true, keyAuth);
            var device = _context.CreateEphemeralDevice("stepup-gate", stepUpKeyStore: store);
            await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            await device.RegisterAccountAsync(NewHandle("su"), Password, token).ConfigureAwait(false);
            var body = new Dictionary<string, object?>(StringComparer.Ordinal) { ["move"] = "money" };

            var refused = await HarnessContext.ExpectApiFailureAsync(
                () => device.SensitiveEchoAsync(body, withStepUp: false, cancellationToken: token),
                "a sensitive operation without step-up").ConfigureAwait(false);
            ExpectRejection(refused, 403, "stepup_required");

            var verified = await device.SensitiveEchoAsync(body, withStepUp: true, cancellationToken: token)
                .ConfigureAwait(false);
            var seen = Json.GetObject(verified, "step_up_key");
            CheckRunner.Expect(Json.GetString(verified, "step_up") == "verified",
                "expected step_up=verified, got " + (Json.GetString(verified, "step_up") ?? "<null>"));
            CheckRunner.Expect(seen is not null
                               && keyAuth.Equals(StepUpKeyAuth.TryParse(Json.GetObject(seen.Value, "key_auth")))
                               && Json.GetNullableBoolean(seen.Value, "policy_downgrade") == false,
                "the verified response must carry the key's auth and no downgrade");

            // The same key, the same request shape, a factor the policy does not
            // accept: the proof is genuine, the claim is wrong.
            var wrong = factor == StepUpKeyAuth.FactorBiometric
                ? StepUpKeyAuth.FactorPasscode
                : StepUpKeyAuth.FactorBiometric;
            var mismatch = await HarnessContext.ExpectApiFailureAsync(
                () => SendStepUpWithFactorAsync(device, store, wrong, body, device.Session!.AccessToken, token),
                "a step-up proof naming the wrong factor").ConfigureAwait(false);
            ExpectRejection(mismatch, 403, "stepup_factor_mismatch");
        }

        private async Task CheckStepUpReenrolAsync(CancellationToken token)
        {
            var store = new SoftwareStepUpKeyStore(true);
            var device = _context.CreateEphemeralDevice("stepup-reenrol", stepUpKeyStore: store);
            await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            var oldKey = device.StepUpKey!;
            var firstSession = await device.RegisterAccountAsync(NewHandle("re"), Password, token)
                .ConfigureAwait(false);

            // The screen lock was removed and the key is gone: a fresh local key,
            // which re-registration can only report as not matching.
            await store.DeleteKeyAsync(token).ConfigureAwait(false);
            var lost = await device.RegisterInstallationAsync(null, token).ConfigureAwait(false);
            var newKey = device.StepUpKey!;
            CheckRunner.Expect(lost.StepUpKeyMatches == false && !device.StepUpUsable,
                "a replaced local key must read as not matching until it is re-enrolled");

            var wrongPassword = await HarnessContext.ExpectApiFailureAsync(
                () => device.ReenrolStepUpKeyAsync("wrong-" + Password, cancellationToken: token),
                "a re-enrolment with the wrong password").ConfigureAwait(false);
            ExpectRejection(wrongPassword, 401, "invalid_credentials");

            using var other = new SoftwareStepUpKeyStore(true);
            await other.GetOrCreateKeyAsync(StepUpKeyAuth.PasscodePerUse, token).ConfigureAwait(false);
            var foreignProof = await HarnessContext.ExpectApiFailureAsync(
                () => ReenrolSignedByAsync(device, firstSession.AccessToken, Password, newKey, other, token),
                "a re-enrolment proof signed by a key other than the one being enrolled").ConfigureAwait(false);
            ExpectRejection(foreignProof, 403, "stepup_reenrol_proof_invalid");

            var stillOld = await device.RegisterInstallationAsync(null, token).ConfigureAwait(false);
            CheckRunner.Expect(stillOld.StepUpKeyMatches == false, "refused re-enrolments must not change the bound key");

            var accepted = await device.ReenrolStepUpKeyAsync(Password, cancellationToken: token).ConfigureAwait(false);
            CheckRunner.Expect(Json.GetBoolean(accepted, "stepup_key_registered"),
                "a valid re-enrolment was not reported as registered");
            CheckRunner.Expect(device.Registration!.StepUpKeyMatches == true && device.StepUpUsable,
                "after re-enrolment the new key must be the bound one");

            var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);
            var oldMatches = await device.Api.RegisterInstallationAsync(
                identity.InstallationId, device.Platform, identity.Key.PublicKey, null,
                identity.Key, oldKey, token).ConfigureAwait(false);
            CheckRunner.Expect(oldMatches.StepUpKeyMatches == false, "the old step-up key must no longer be bound");

            // A second account on the same installation needs only the
            // installation key. Its re-enrolled key must not pass step-up for the
            // first account, or a signing oracle could open its own account and
            // unlock the victim's sensitive operations.
            var settings = await SettingsAsync(token).ConfigureAwait(false);
            if (!(Setting(settings, "stepup_required_paths") ?? string.Empty).Contains(SensitivePath))
            {
                return;
            }

            const string secondPassword = "Second0ne123";
            await device.RegisterAccountAsync(NewHandle("re2"), secondPassword, token).ConfigureAwait(false);
            await store.DeleteKeyAsync(token).ConfigureAwait(false);
            await device.PrepareStepUpKeyAsync(token).ConfigureAwait(false);
            await device.ReenrolStepUpKeyAsync(secondPassword, cancellationToken: token).ConfigureAwait(false);

            var body = Json.SerializeToUtf8Bytes(
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["move"] = "money" });
            var crossAccount = await HarnessContext.ExpectApiFailureAsync(
                () => device.SendStepUpProtectedAsync("POST", SensitivePath, body, firstSession.AccessToken,
                    "cross-account step-up", token),
                "the first account passing step-up with the second account's key").ConfigureAwait(false);
            ExpectRejection(crossAccount, 403, "stepup_key_other_account");

            var own = await device.SensitiveEchoAsync(
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["move"] = "money" },
                withStepUp: true,
                cancellationToken: token).ConfigureAwait(false);
            CheckRunner.Expect(Json.GetString(own, "step_up") == "verified",
                "the second account's own key must pass step-up");
        }

        private async Task CheckDeviceAccountBandsAsync(CancellationToken token)
        {
            var device = _context.CreateEphemeralDevice("account-bands");
            var health = await device.Api.HealthReadyAsync(token).ConfigureAwait(false);
            var enforce = Json.GetString(health, "device_policy_mode") == "enforce";
            var settings = RiskSettings(health);
            var elevated = SettingInt(settings, "device_accounts_elevated_count", 2);
            var review = SettingInt(settings, "device_accounts_review_count", 3);
            var block = SettingInt(settings, "device_accounts_block_count", 4);
            var refuses = (Setting(settings, "elevated_risk_refuses") ?? "0").Trim().ToLowerInvariant()
                is "1" or "true" or "yes" or "on";
            if (!(1 < elevated && elevated < review && review < block && block <= 10))
            {
                throw new SkipCheckException("band layout " + elevated + "/" + review + "/" + block
                                             + " is not ordered within 10 accounts");
            }

            await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
            var results = new Dictionary<int, (AccountSession? Session, DeviceTrustApiException? Error, RiskPolicyDecision? Policy)>();
            for (var n = 1; n <= block; n++)
            {
                try
                {
                    var session = await device.RegisterAccountAsync(NewHandle("band" + n), Password, token)
                        .ConfigureAwait(false);
                    results[n] = (session, null, session.Policy);
                }
                catch (DeviceTrustApiException error)
                {
                    results[n] = (null, error, PolicyOf(error));
                    break;
                }
            }

            var atElevated = results[elevated];
            CheckRunner.Expect(Codes(atElevated.Policy).Contains("device_has_multiple_accounts"),
                "account " + elevated + " must be scored device_has_multiple_accounts, got "
                + Report.Join(Codes(atElevated.Policy)));
            if (enforce && refuses)
            {
                CheckRunner.Expect(atElevated.Error?.StatusCode == 403 && atElevated.Error.Code == "risk_step_up_required",
                    "elevated_risk_refuses=1: account " + elevated + " expected 403 risk_step_up_required");
                return;
            }

            for (var n = 1; n < review; n++)
            {
                CheckRunner.Expect(results[n].Session is not null,
                    "account " + n + " (at most the elevated band) must never be refused, got "
                    + (results[n].Error?.Code ?? "<no session>"));
                var me = await device.SendProtectedAsync("GET", "/v1/account/me", null,
                    results[n].Session!.AccessToken, cancellationToken: token).ConfigureAwait(false);
                CheckRunner.Expect(Json.GetString(me, "access_proof") == "accepted",
                    "account " + n + " on the shared device must keep working");
            }

            var atReview = results[review];
            CheckRunner.Expect(Codes(atReview.Policy).Contains("device_has_many_accounts")
                               && atReview.Policy?.RecommendedAction is "review" or "block",
                "account " + review + " must be scored for review, got "
                + (atReview.Policy?.RecommendedAction ?? "<none>") + " " + Report.Join(Codes(atReview.Policy)));
            if (enforce)
            {
                CheckRunner.Expect(atReview.Error?.StatusCode == 403
                                   && atReview.Error.Code is "risk_review_required" or "risk_policy_blocked",
                    "enforce: account " + review + " must be held for review, got "
                    + (atReview.Error?.Code ?? "<accepted>"));
                return;
            }

            var atBlock = results[block];
            CheckRunner.Expect(atBlock.Session is not null
                               && Codes(atBlock.Policy).Contains("device_account_count_block_threshold")
                               && atBlock.Policy?.RecommendedAction == "block",
                "account " + block + " must be scored block, got "
                + (atBlock.Policy?.RecommendedAction ?? "<none>") + " " + Report.Join(Codes(atBlock.Policy)));
        }

        private async Task CheckParallelClientsAsync(CancellationToken token)
        {
            // Four phone-like clients at once, three rounds. Every other check is
            // sequential, which is how a heap-corrupting ODBC pool on SQL Server
            // went unseen until two handsets bootstrapped together (DESIGN.md 55).
            var failures = new List<string>();
            var slowest = (Seconds: 0.0, Step: string.Empty);
            var gate = new object();

            for (var round = 0; round < 3; round++)
            {
                var devices = Enumerable.Range(0, 4)
                    .Select(i => _context.CreateEphemeralDevice(
                        "parallel-r" + round.ToString(CultureInfo.InvariantCulture) + "c" + i.ToString(CultureInfo.InvariantCulture)))
                    .ToList();

                await Task.WhenAll(devices.Select(async (device, index) =>
                {
                    var steps = new List<(string Step, double Seconds)>();
                    try
                    {
                        var clock = Stopwatch.StartNew();
                        await device.RegisterInstallationAsync(FreshHint(), token).ConfigureAwait(false);
                        steps.Add(("register", clock.Elapsed.TotalSeconds));
                        clock.Restart();
                        var deviceToken = await device.AcquireDeviceTokenAsync(token).ConfigureAwait(false);
                        steps.Add(("challenge+verify", clock.Elapsed.TotalSeconds));
                        clock.Restart();
                        await device.SubmitIntegrityReportAsync(deviceToken, token).ConfigureAwait(false);
                        steps.Add(("integrity", clock.Elapsed.TotalSeconds));
                        clock.Restart();
                        await device.GetDeviceSummaryAsync(deviceToken, token).ConfigureAwait(false);
                        steps.Add(("device/me", clock.Elapsed.TotalSeconds));
                    }
                    catch (Exception error)
                    {
                        lock (gate)
                        {
                            failures.Add("c" + index.ToString(CultureInfo.InvariantCulture) + ": "
                                         + (error is DeviceTrustException dt ? dt.Code + " " : string.Empty)
                                         + error.Message);
                        }
                    }

                    lock (gate)
                    {
                        foreach (var step in steps.Where(step => step.Seconds > slowest.Seconds))
                        {
                            slowest = (step.Seconds, step.Step);
                        }
                    }
                })).ConfigureAwait(false);
            }

            CheckRunner.Expect(failures.Count == 0,
                failures.Count + " of 12 parallel flows failed: " + string.Join("; ", failures.Take(3)));
            CheckRunner.Expect(slowest.Seconds < 10.0,
                "slowest step " + slowest.Step + " took "
                + slowest.Seconds.ToString("0.0", CultureInfo.InvariantCulture)
                + "s under parallel load (the handset timeout is 15s)");
        }

        private static async Task<JsonElement> SendStepUpWithFactorAsync(
            DeviceTrustClient device,
            IStepUpKeyStore store,
            string factor,
            IReadOnlyDictionary<string, object?> body,
            string accessToken,
            CancellationToken token)
        {
            var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);
            var nonce = AccessProof.CreateNonce();
            var proof = DeviceTrustClient.BuildStepUpProof(
                identity.InstallationId, factor, nonce, AccessProof.CurrentTimestamp());
            var signature = await store.SignAsync(proof, "conformance", token).ConfigureAwait(false);
            var fixture = await device.BuildAccessProofFixtureAsync(
                "POST", SensitivePath, Json.SerializeToUtf8Bytes(body), accessToken, nonce: nonce,
                cancellationToken: token).ConfigureAwait(false);
            return await device.SendAccessProofFixtureAsync(
                fixture,
                additionalHeaders: new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [DeviceTrustClient.StepUpProofHeader] = Base64Url.Encode(proof),
                    [DeviceTrustClient.StepUpSignatureHeader] = Base64Url.Encode(signature),
                },
                cancellationToken: token).ConfigureAwait(false);
        }

        /// <summary>
        /// A re-enrolment whose proof names <paramref name="newKey"/> but is signed
        /// by <paramref name="signer"/>: the shape of an attacker who has the
        /// password but cannot make the new key sign.
        /// </summary>
        private static async Task<JsonElement> ReenrolSignedByAsync(
            DeviceTrustClient device,
            string accessToken,
            string password,
            StepUpKeyMetadata newKey,
            IStepUpKeyStore signer,
            CancellationToken token)
        {
            var identity = await device.LoadIdentityAsync(token).ConfigureAwait(false);
            var nonce = AccessProof.CreateNonce();
            var proof = Serialize(writer =>
            {
                writer.WriteNumber("version", 1);
                writer.WriteString("purpose", "stepup_reenrol");
                writer.WriteString("installation_id", identity.InstallationId);
                writer.WriteString("stepup_key_thumbprint", newKey.Thumbprint);
                writer.WriteString("nonce", nonce);
                writer.WriteNumber("timestamp", AccessProof.CurrentTimestamp());
            });
            var signature = await signer.SignAsync(proof, "conformance", token).ConfigureAwait(false);
            var body = Serialize(writer =>
            {
                writer.WriteString("password", password);
                writer.WritePropertyName("stepup_public_key");
                newKey.PublicKey.Write(writer);
                writer.WritePropertyName("stepup_key_auth");
                newKey.Auth.Write(writer);
                writer.WriteString("stepup_key_proof", Base64Url.Encode(proof));
                writer.WriteString("stepup_key_signature", Base64Url.Encode(signature));
            });
            var fixture = await device.BuildAccessProofFixtureAsync(
                "POST", "/v1/installations/stepup-key", body, accessToken, nonce: nonce,
                cancellationToken: token).ConfigureAwait(false);
            return await device.SendAccessProofFixtureAsync(fixture, cancellationToken: token).ConfigureAwait(false);
        }

        private static byte[] Serialize(Action<Utf8JsonWriter> members)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                members(writer);
                writer.WriteEndObject();
            }

            return buffer.ToArray();
        }

        private async Task<IReadOnlyDictionary<string, JsonElement>> SettingsAsync(CancellationToken token)
        {
            var probe = _context.CreateEphemeralDevice("settings");
            return RiskSettings(await probe.Api.HealthReadyAsync(token).ConfigureAwait(false));
        }

        private static IReadOnlyDictionary<string, JsonElement> RiskSettings(JsonElement health)
        {
            var flags = Json.GetObject(health, "scoring_flags");
            var settings = flags is null ? null : Json.GetObject(flags.Value, "risk_policy_settings");
            return settings is null
                ? new Dictionary<string, JsonElement>()
                : Json.ToDictionary(settings.Value);
        }

        private static string? Setting(IReadOnlyDictionary<string, JsonElement> settings, string key)
        {
            return settings.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        private static int SettingInt(IReadOnlyDictionary<string, JsonElement> settings, string key, int fallback)
        {
            return int.TryParse(Setting(settings, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
                ? value
                : fallback;
        }

        private static RiskPolicyDecision? PolicyOf(DeviceTrustApiException error)
        {
            return error.Details.TryGetValue("policy", out var policy) && policy.ValueKind == JsonValueKind.Object
                ? RiskPolicyDecision.Parse(policy)
                : null;
        }

        private static List<string> Codes(RiskPolicyDecision? policy)
        {
            return policy?.Reasons.Select(reason => reason.Code).ToList() ?? new List<string>();
        }

        private static void ExpectRejection(DeviceTrustApiException failure, int status, string code)
        {
            CheckRunner.Expect(failure.StatusCode == status && failure.Code == code,
                "expected " + status.ToString(CultureInfo.InvariantCulture) + " " + code + ", got "
                + failure.StatusCode.ToString(CultureInfo.InvariantCulture) + " " + (failure.Code ?? "<no code>"));
        }

        private static ReinstallHint FreshHint()
        {
            return new ReinstallHint("android_id_sha256", ConformanceProbeCollector.RandomHintDigest());
        }

        private static string NewHandle(string prefix)
        {
            var bytes = new byte[4];
            RandomNumberGenerator.Fill(bytes);
            return "dotnet-" + prefix + "-" + Hex.Encode(bytes);
        }

        private static string Describe(bool? value) => value is null ? "null" : value.Value ? "true" : "false";
    }
}
