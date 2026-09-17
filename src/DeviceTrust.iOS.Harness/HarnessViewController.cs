using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using CoreGraphics;
using DeviceTrust.Client;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Maui.Apple;
using DeviceTrust.Client.Protocol;
using Foundation;
using UIKit;

namespace DeviceTrust.iOS.Harness
{
    /// <summary>
    /// The on-device harness, with a button per battery item.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The iOS counterpart of the Android harness, and it carries buttons for
    /// the same reason: the person holding the phone needs to press one thing
    /// and read a verdict. Everything is also written to the system log with the
    /// tag <c>DTHARNESS</c>, so a run can be read over USB without watching the
    /// screen.
    /// </para>
    /// <para>
    /// Items 12, 13 and 15 differ from Android by platform, and the buttons say
    /// so. Deleting an iOS app does not destroy its Keychain items, so "uninstall
    /// and reinstall" proves nothing about re-enrolment here; the iOS parallel is
    /// an explicit <b>Delete key</b>. Item 15 is the mirror image: reinstall
    /// <i>without</i> deleting the key and the same installation must come back.
    /// </para>
    /// </remarks>
    public sealed class HarnessViewController : UIViewController
    {
        private const string LogTag = "DTHARNESS";

        private readonly StringBuilder _transcript = new StringBuilder();
        private readonly object _transcriptLock = new object();
        private readonly List<UIButton> _buttons = new List<UIButton>();

        private UITextField? _baseUrl;
        private UITextField? _handle;
        private UITextField? _password;
        private UITextField? _victimInstallation;
        private UITextField? _stolenAccess;
        private UITextField? _stolenRefresh;
        private UILabel? _status;
        private UILabel? _identity;
        private UITextView? _output;
        private bool _busy;

        /// <inheritdoc />
        public override void ViewDidLoad()
        {
            base.ViewDidLoad();
            Title = "DeviceFingerprinting .NET";
            View!.BackgroundColor = UIColor.SystemBackground;
            BuildUserInterface();
        }

        // ---------------------------------------------------------------- UI

        private void BuildUserInterface()
        {
            var stack = new UIStackView
            {
                Axis = UILayoutConstraintAxis.Vertical,
                Spacing = 8,
                TranslatesAutoresizingMaskIntoConstraints = false,
                LayoutMarginsRelativeArrangement = true,
                LayoutMargins = new UIEdgeInsets(16, 16, 16, 16),
            };

            _status = Label("Not started", bold: true, size: 16);
            stack.AddArrangedSubview(_status);

            stack.AddArrangedSubview(Label("Endpoint", bold: true, size: 13));
            _baseUrl = Field("https://<host>.nip.io", Preference("api_base_url", string.Empty));
            stack.AddArrangedSubview(_baseUrl);

            stack.AddArrangedSubview(Label("Installation and device record", bold: true, size: 13));
            _identity = Label("No identity loaded yet.", bold: false, size: 11);
            stack.AddArrangedSubview(_identity);

            stack.AddArrangedSubview(Button("Enrol + native integrity scan", () => Run("scan", ScanAsync)));
            stack.AddArrangedSubview(Button("Show installation key", () => RunLocal("keyinfo", KeyInfoAsync)));
            stack.AddArrangedSubview(Button("Show code-signing identity", () => RunLocal("signing", SigningAsync)));

            stack.AddArrangedSubview(Label("Account", bold: true, size: 13));
            _handle = Field("handle", Preference("handle", "iphone-net"));
            stack.AddArrangedSubview(_handle);
            _password = Field("password", Preference("password", "Passw0rd123"));
            stack.AddArrangedSubview(_password);
            stack.AddArrangedSubview(Button("Create account", () => Run("account-register", c => AccountAsync(c, "register"))));
            stack.AddArrangedSubview(Button("Log in", () => Run("account-login", c => AccountAsync(c, "login"))));
            stack.AddArrangedSubview(Button("Evaluate current account risk", () => Run("policy", PolicyAsync)));

            stack.AddArrangedSubview(Label("Proof of possession", bold: true, size: 13));
            stack.AddArrangedSubview(Button("Test protected access", () => Run("bound-access", BoundAccessAsync)));
            stack.AddArrangedSubview(Button("Test bound refresh", () => Run("bound-refresh", BoundRefreshAsync)));

            stack.AddArrangedSubview(Label("Access-proof boundary tests (items 5-8)", bold: true, size: 13));
            stack.AddArrangedSubview(Button("Run all four in sequence", () => Run("boundary", BoundaryAllAsync)));

            stack.AddArrangedSubview(Label("Cross-device tests (items 3-4)", bold: true, size: 13));
            stack.AddArrangedSubview(Label(
                "Mint here, paste into the Android handset, and replay there. One phone mints, "
                + "the other is refused because it cannot produce the signature.", bold: false, size: 11));
            stack.AddArrangedSubview(Button("Mint + show my tokens (test only)", () => Run("stolen-mint", StolenMintAsync)));
            _victimInstallation = Field("victim installation_id", string.Empty);
            stack.AddArrangedSubview(_victimInstallation);
            _stolenAccess = Field("stolen access token", string.Empty);
            stack.AddArrangedSubview(_stolenAccess);
            _stolenRefresh = Field("stolen refresh token", string.Empty);
            stack.AddArrangedSubview(_stolenRefresh);
            stack.AddArrangedSubview(Button("Attempt stolen protected request", () => Run("stolen-access", StolenAccessAsync)));
            stack.AddArrangedSubview(Button("Attempt stolen refresh", () => Run("stolen-refresh", StolenRefreshAsync)));

            stack.AddArrangedSubview(Label("Local state", bold: true, size: 13));
            stack.AddArrangedSubview(Button("Clear local account tokens", () => Run("clear-session", ClearSessionAsync)));
            // The iOS parallel of an Android uninstall. Deleting the app leaves
            // the Secure Enclave key in place, so only this genuinely forces a
            // new installation identity -- items 12 and 13.
            stack.AddArrangedSubview(Button("Delete key (items 12/13: forces a NEW hardware key)",
                () => RunLocal("reset", ResetAsync)));

            stack.AddArrangedSubview(Label("Result", bold: true, size: 13));
            _output = new UITextView
            {
                Editable = false,
                Font = UIFont.FromName("Menlo", 10) ?? UIFont.SystemFontOfSize(10),
                Text = "-",
                ScrollEnabled = false,
                TranslatesAutoresizingMaskIntoConstraints = false,
            };
            stack.AddArrangedSubview(_output);

            var scroll = new UIScrollView { TranslatesAutoresizingMaskIntoConstraints = false };
            scroll.AddSubview(stack);
            View!.AddSubview(scroll);

            var guide = View.SafeAreaLayoutGuide;
            NSLayoutConstraint.ActivateConstraints(new[]
            {
                scroll.TopAnchor.ConstraintEqualTo(guide.TopAnchor),
                scroll.BottomAnchor.ConstraintEqualTo(guide.BottomAnchor),
                scroll.LeadingAnchor.ConstraintEqualTo(guide.LeadingAnchor),
                scroll.TrailingAnchor.ConstraintEqualTo(guide.TrailingAnchor),
                stack.TopAnchor.ConstraintEqualTo(scroll.ContentLayoutGuide.TopAnchor),
                stack.BottomAnchor.ConstraintEqualTo(scroll.ContentLayoutGuide.BottomAnchor),
                stack.LeadingAnchor.ConstraintEqualTo(scroll.ContentLayoutGuide.LeadingAnchor),
                stack.WidthAnchor.ConstraintEqualTo(scroll.FrameLayoutGuide.WidthAnchor),
            });
        }

        private UILabel Label(string text, bool bold, float size)
        {
            return new UILabel
            {
                Text = text,
                Lines = 0,
                Font = bold ? UIFont.BoldSystemFontOfSize(size) : UIFont.SystemFontOfSize(size),
                TranslatesAutoresizingMaskIntoConstraints = false,
            };
        }

        private UITextField Field(string placeholder, string value)
        {
            var field = new UITextField
            {
                Placeholder = placeholder,
                Text = value,
                BorderStyle = UITextBorderStyle.RoundedRect,
                AutocorrectionType = UITextAutocorrectionType.No,
                AutocapitalizationType = UITextAutocapitalizationType.None,
                Font = UIFont.SystemFontOfSize(12),
                TranslatesAutoresizingMaskIntoConstraints = false,
            };
            field.HeightAnchor.ConstraintEqualTo(32).Active = true;
            return field;
        }

        private UIButton Button(string title, Action action)
        {
            var button = UIButton.FromType(UIButtonType.System);
            button.SetTitle(title, UIControlState.Normal);
            button.TitleLabel!.Font = UIFont.SystemFontOfSize(13);
            button.TitleLabel.Lines = 0;
            button.HorizontalAlignment = UIControlContentHorizontalAlignment.Left;
            button.TranslatesAutoresizingMaskIntoConstraints = false;
            button.TouchUpInside += (_, _) => action();
            _buttons.Add(button);
            return button;
        }

        // ----------------------------------------------------------- plumbing

        private void Run(string name, Func<DeviceTrustClient, Task> body)
        {
            Start(name, async () =>
            {
                var endpoint = (_baseUrl?.Text ?? string.Empty).Trim();
                var options = new DeviceTrustOptions
                {
                    BaseUrl = string.IsNullOrEmpty(endpoint) ? null : endpoint,
                    NetworkTimeout = TimeSpan.FromSeconds(30),
                };

                using var client = new DeviceTrustClient(
                    options,
                    new SecureEnclaveInstallationKeyStore(),
                    // Keychain, not a file. An iOS reinstall wipes the data
                    // container but leaves the Keychain, so a file-backed store
                    // would resurrect the same key under a new installation id.
                    new KeychainInstallationStateStore(),
                    new AppleIntegrityCollector());

                await client.RestoreSessionAsync().ConfigureAwait(false);
                await body(client).ConfigureAwait(false);
            });
        }

        private void RunLocal(string name, Func<SecureEnclaveInstallationKeyStore, Task> body)
        {
            // Local actions take no endpoint. Showing the key or deleting it
            // touches only this device, and a freshly installed phone has no
            // endpoint configured yet -- gating those behind one would make the
            // single screen that can say whether a key exists refuse to run.
            Start(name, () => body(new SecureEnclaveInstallationKeyStore()));
        }

        private void Start(string name, Func<Task> body)
        {
            if (_busy)
            {
                return;
            }

            _busy = true;
            SetButtonsEnabled(false);
            lock (_transcriptLock)
            {
                _transcript.Clear();
            }
            SetStatus("Running " + name + "...");
            SavePreferences();

            var started = DateTimeOffset.UtcNow;
            Task.Run(async () =>
            {
                var ok = true;
                try
                {
                    await body().ConfigureAwait(false);
                }
                catch (DeviceTrustApiException error)
                {
                    ok = false;
                    Line("SERVER-REJECTED HTTP "
                         + error.StatusCode.ToString(CultureInfo.InvariantCulture)
                         + " " + (error.Code ?? "<no code>") + " -- " + error.Message);
                }
                catch (Exception error)
                {
                    ok = false;
                    Line("FAILED " + error.GetType().Name + ": " + error.Message);
                }
                finally
                {
                    Line("=== DONE action=" + name + " ok=" + (ok ? "1" : "0") + " seconds="
                         + (DateTimeOffset.UtcNow - started).TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)
                         + " ===");
                    var finished = ok;
                    BeginInvokeOnMainThread(() =>
                    {
                        _busy = false;
                        SetButtonsEnabled(true);
                        SetStatus((finished ? "Finished: " : "Failed: ") + name);
                    });
                }
            });
        }

        // ------------------------------------------------------------ actions

        private async Task KeyInfoAsync(SecureEnclaveInstallationKeyStore keyStore)
        {
            var metadata = await keyStore.GetOrCreateKeyAsync().ConfigureAwait(false);
            Line("provider               " + metadata.Provider);
            Line("security_level         " + metadata.SecurityLevel);
            Line("hardware_backed        " + metadata.HardwareBacked);
            Line("private_key_exportable " + metadata.PrivateKeyExportable);
            // Item 15 reads this pair: after deleting and reinstalling the app
            // WITHOUT deleting the key, both must be unchanged.
            Line("created_this_launch    " + metadata.Created);
            Line("key_thumbprint         " + metadata.PublicKey.Thumbprint);
            SetIdentity("Thumbprint " + metadata.PublicKey.Thumbprint + "\n"
                        + metadata.SecurityLevel + ", hardware_backed=" + metadata.HardwareBacked
                        + "\ncreated_this_launch=" + metadata.Created);
        }

        private Task SigningAsync(SecureEnclaveInstallationKeyStore keyStore)
        {
            // Reads the app's own Mach-O signature, which is what the server's
            // signing_identifier contract expects: the CodeDirectory identifier,
            // not the application-identifier entitlement.
            var probe = new AppleIntegrityCollector();
            var collection = probe.CollectAsync(new[] { "code_signing", "app_identity" }, "local")
                .GetAwaiter().GetResult();
            foreach (var entry in collection.Probes)
            {
                Line("--- " + entry.Key);
                foreach (var field in entry.Value.Fields)
                {
                    Line("  " + field.Key + " = " + field.Value);
                }
            }

            return Task.CompletedTask;
        }

        private async Task ResetAsync(SecureEnclaveInstallationKeyStore keyStore)
        {
            await keyStore.DeleteKeyAsync().ConfigureAwait(false);
            await new KeychainInstallationStateStore().ClearAsync().ConfigureAwait(false);
            Line("Secure Enclave key deleted and Keychain state cleared.");
            Line("This is the iOS equivalent of an Android uninstall. Deleting the APP would NOT");
            Line("have done it: iOS keeps Keychain items across app deletion, which is what item 15");
            Line("asserts. The next enrolment presents a NEW hardware key, and the reinstall hint is");
            Line("what should correlate it back to the same device_id.");
        }

        private async Task ScanAsync(DeviceTrustClient client)
        {
            var registration = await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var identity = await client.LoadIdentityAsync().ConfigureAwait(false);
            Line("installation_id        " + registration.InstallationId);
            Line("device_id              " + registration.DeviceId);
            Line("recognition            " + registration.Method + " / " + registration.Confidence);
            Line("key_thumbprint         " + identity.KeyThumbprint);
            Line("created_this_launch    " + identity.Key.Created);
            Line("security_level         " + identity.Key.SecurityLevel
                 + "  hardware_backed=" + identity.Key.HardwareBacked);

            var deviceToken = await client.AcquireDeviceTokenAsync().ConfigureAwait(false);
            var decision = await client.SubmitIntegrityReportAsync(deviceToken).ConfigureAwait(false);

            var probes = client.LastIntegrityCollection?.Probes;
            if (probes is not null && probes.TryGetValue("code_integrity", out var code))
            {
                Line("code_integrity checked=" + Field(code, "checked"));
                Line("  app compared=" + Field(code, "app_compared_bytes")
                     + " diff=" + Field(code, "app_diff_bytes")
                     + " images=" + Field(code, "app_images_compared"));
                // Never a silent zero: the shared cache has no backing files, so
                // the system buckets are reported unreadable with a reason.
                Line("  system unreadable=" + Field(code, "system_images_unreadable")
                     + " reason=" + Field(code, "system_bucket_reason"));
            }

            if (probes is not null && probes.TryGetValue("code_signing", out var signing))
            {
                Line("code_signing signed=" + Field(signing, "signed")
                     + " identifier=" + Field(signing, "signing_identifier")
                     + " team=" + Field(signing, "team_identifier")
                     + " get_task_allow=" + Field(signing, "get_task_allow"));
            }

            Line("probes " + string.Join(",", client.LastRequiredProbes));
            Line("INTEGRITY score=" + decision.Score.ToString(CultureInfo.InvariantCulture)
                 + " verdict=" + decision.Verdict + " mode=" + decision.Mode);
            foreach (var reason in decision.Reasons)
            {
                Line("  REASON " + reason.Code + " +"
                     + reason.Points.ToString(CultureInfo.InvariantCulture)
                     + (reason.Hard ? " [HARD]" : string.Empty));
            }

            if (decision.Reasons.Count == 0)
            {
                Line("  REASON <none>");
            }

            var summary = await client.GetDeviceSummaryAsync(deviceToken).ConfigureAwait(false);
            Line("installations_on_device " + summary.InstallationCount);
            SetIdentity("Installation " + registration.InstallationId
                        + "\nDevice " + registration.DeviceId
                        + "\nRecognition " + registration.Method + " / " + registration.Confidence
                        + "\nIntegrity " + decision.Score + "/100 " + decision.Verdict);
        }

        private async Task AccountAsync(DeviceTrustClient client, string mode)
        {
            var handle = (_handle?.Text ?? string.Empty).Trim();
            var password = (_password?.Text ?? string.Empty).Trim();
            if (handle.Length == 0 || password.Length == 0)
            {
                Line("A handle and a password are required.");
                return;
            }

            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var session = mode == "login"
                ? await client.LoginAccountAsync(handle, password).ConfigureAwait(false)
                : await client.RegisterAccountAsync(handle, password).ConfigureAwait(false);

            Line("ITEM PASS  2. account " + mode + " through the enforce gate");
            Line("account_id " + session.AccountId);
        }

        private async Task PolicyAsync(DeviceTrustClient client)
        {
            var policy = await client.GetPolicyAsync().ConfigureAwait(false);
            Line("policy mode=" + policy.Mode + " score=" + policy.Score
                 + " recommended=" + policy.RecommendedAction + " effective=" + policy.EffectiveAction);
        }

        private async Task BoundAccessAsync(DeviceTrustClient client)
        {
            var me = await client.GetAccountMeAsync().ConfigureAwait(false);
            var probeId = Guid.NewGuid().ToString();
            var echo = await client.ProtectedEchoAsync(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["probe_id"] = probeId,
                ["message"] = "proof-of-possession body binding test",
            }).ConfigureAwait(false);

            var echoed = Json.GetObject(echo, "echo");
            var ok = Json.GetString(me, "access_proof") == "accepted"
                     && Json.GetString(echo, "access_proof") == "accepted"
                     && echoed is not null && Json.GetString(echoed.Value, "probe_id") == probeId;
            Line(ok
                ? "ITEM PASS  legitimate access proof accepted (GET and POST, body bound)"
                : "ITEM FAIL  the protected API returned an unexpected proof result");
        }

        private async Task BoundRefreshAsync(DeviceTrustClient client)
        {
            var rotated = await client.RefreshAccountSessionAsync().ConfigureAwait(false);
            await client.GetAccountMeAsync().ConfigureAwait(false);
            Line("ITEM PASS  bound refresh rotated and the new access token works");
            Line("account_id " + rotated.AccountId);
        }

        private async Task BoundaryAllAsync(DeviceTrustClient client)
        {
            if (client.Session is null)
            {
                await AccountAsync(client, "register").ConfigureAwait(false);
            }

            // Items 5-8 must run within 10 minutes of a refresh, or an expired
            // access token makes them inconclusive.
            var session = await client.RefreshAccountSessionAsync().ConfigureAwait(false);
            Line("refreshed -- items 5-8 start inside the 10 minute window");

            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["probe"] = "replay",
            });
            var fixture = await client.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", body, session.AccessToken).ConfigureAwait(false);
            var first = await client.SendAccessProofFixtureAsync(fixture).ConfigureAwait(false);
            if (Json.GetString(first, "access_proof") == "accepted")
            {
                await ExpectAsync("5. exact replay", 401, "access_proof_replay",
                    () => client.SendAccessProofFixtureAsync(fixture)).ConfigureAwait(false);
            }
            else
            {
                Line("ITEM FAIL  5. replay -- the control request was not accepted");
            }

            var signed = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal) { ["amount"] = 1 });
            var tampered = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal) { ["amount"] = 1000000 });
            var bodyFixture = await client.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", signed, session.AccessToken).ConfigureAwait(false);
            await ExpectAsync("6. body tampering", 401, "access_proof_body_mismatch",
                () => client.SendAccessProofFixtureAsync(bodyFixture, actualBody: tampered)).ConfigureAwait(false);

            var pathFixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/not-the-requested-route", null, session.AccessToken).ConfigureAwait(false);
            await ExpectAsync("7a. path tampering", 401, "access_proof_path_mismatch",
                () => client.SendAccessProofFixtureAsync(pathFixture, actualMethod: "GET", actualPath: "/v1/account/me"))
                .ConfigureAwait(false);

            var methodFixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/protected-echo", null, session.AccessToken).ConfigureAwait(false);
            var methodBody = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["message"] = "actual POST while the proof says GET",
            });
            await ExpectAsync("7b. method tampering", 401, "access_proof_method_mismatch",
                () => client.SendAccessProofFixtureAsync(methodFixture, actualMethod: "POST",
                    actualPath: "/v1/account/protected-echo", actualBody: methodBody)).ConfigureAwait(false);

            var staleFixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/me", null, session.AccessToken,
                timestampSeconds: AccessProof.CurrentTimestamp() - 180).ConfigureAwait(false);
            await ExpectAsync("8. stale timestamp", 401, "access_proof_timestamp_outside_window",
                () => client.SendAccessProofFixtureAsync(staleFixture)).ConfigureAwait(false);
        }

        private async Task StolenMintAsync(DeviceTrustClient client)
        {
            var handle = (_handle?.Text ?? "mint").Trim() + "-" + Guid.NewGuid().ToString("N").Substring(0, 6);
            var password = (_password?.Text ?? "Passw0rd123").Trim();
            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var session = await client.RegisterAccountAsync(handle, password).ConfigureAwait(false);
            var identity = await client.LoadIdentityAsync().ConfigureAwait(false);

            Line("MINT handle             " + handle);
            Line("MINT installation_id    " + identity.InstallationId);
            Line("MINT access_token       " + session.AccessToken);
            Line("MINT refresh_token      " + session.RefreshToken);
        }

        private async Task StolenAccessAsync(DeviceTrustClient client)
        {
            var token = (_stolenAccess?.Text ?? string.Empty).Trim();
            var victim = (_victimInstallation?.Text ?? string.Empty).Trim();
            if (token.Length == 0 || victim.Length == 0)
            {
                Line("Paste the other phone's access token and installation id first.");
                return;
            }

            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            // Claim the victim's installation id inside the proof and sign with
            // this phone's key; using our own id would fail earlier on an id
            // mismatch and never exercise the signature check.
            var fixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/me", null, token, proofInstallationId: victim).ConfigureAwait(false);
            await ExpectAsync("3. stolen access token", 401, "invalid_installation_signature",
                () => client.SendAccessProofFixtureAsync(fixture)).ConfigureAwait(false);
        }

        private async Task StolenRefreshAsync(DeviceTrustClient client)
        {
            var token = (_stolenRefresh?.Text ?? string.Empty).Trim();
            if (token.Length == 0)
            {
                Line("Paste the other phone's refresh token first.");
                return;
            }

            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var challenge = await client.Api.RefreshChallengeAsync(token).ConfigureAwait(false);
            Line("refresh challenge HTTP 200 -- the stolen token itself is genuine");
            var payload = Json.RequireString(challenge, "payload");
            var challengeId = Json.RequireString(challenge, "challenge_id");
            var signature = await client.SignBase64UrlPayloadAsync(payload).ConfigureAwait(false);
            await ExpectAsync("4. stolen refresh token", 401, "invalid_installation_signature",
                () => client.Api.RefreshAsync(token, challengeId, payload, signature)).ConfigureAwait(false);
        }

        private async Task ClearSessionAsync(DeviceTrustClient client)
        {
            await client.ClearSessionAsync().ConfigureAwait(false);
            Line("Local account tokens cleared. The Secure Enclave key is untouched.");
        }

        // ----------------------------------------------------------- helpers

        private async Task ExpectAsync(string name, int status, string code, Func<Task> operation)
        {
            try
            {
                await operation().ConfigureAwait(false);
                Line("ITEM FAIL  " + name + " -- accepted, which is a security failure not a test failure");
            }
            catch (DeviceTrustApiException error)
            {
                if (error.StatusCode == status && error.Code == code)
                {
                    Line("ITEM PASS  " + name + "  -> HTTP "
                         + status.ToString(CultureInfo.InvariantCulture) + " " + code);
                }
                else
                {
                    Line("ITEM FAIL  " + name + " -- expected HTTP "
                         + status.ToString(CultureInfo.InvariantCulture) + " " + code + ", got HTTP "
                         + error.StatusCode.ToString(CultureInfo.InvariantCulture)
                         + " " + (error.Code ?? "<none>"));
                }
            }
        }

        private static string Field(DeviceTrust.Client.Integrity.ProbeResult probe, string name)
        {
            return probe.Fields.TryGetValue(name, out var value) && value is not null
                ? Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty
                : string.Empty;
        }

        private ReinstallHint? ReadReinstallHint()
        {
            // identifierForVendor is the iOS analogue of the Android ID. It is
            // stable for this vendor's apps on this device, and it is hashed with
            // the same domain separator the other clients use so the server
            // correlates to the same device record.
            var idfv = UIDevice.CurrentDevice.IdentifierForVendor?.AsString();
            return ReinstallHint.FromRawIdentifier("idfv_sha256", "idfv", idfv);
        }

        private static string Preference(string key, string fallback)
        {
            var value = NSUserDefaults.StandardUserDefaults.StringForKey(key);
            return string.IsNullOrEmpty(value) ? fallback : value!;
        }

        private void SavePreferences()
        {
            var defaults = NSUserDefaults.StandardUserDefaults;
            defaults.SetString(_baseUrl?.Text ?? string.Empty, "api_base_url");
            defaults.SetString(_handle?.Text ?? string.Empty, "handle");
            defaults.SetString(_password?.Text ?? string.Empty, "password");
        }

        private void SetButtonsEnabled(bool enabled)
        {
            foreach (var button in _buttons)
            {
                button.Enabled = enabled;
            }
        }

        private void SetStatus(string text)
        {
            BeginInvokeOnMainThread(() =>
            {
                if (_status is not null)
                {
                    _status.Text = text;
                }
            });
        }

        private void SetIdentity(string text)
        {
            BeginInvokeOnMainThread(() =>
            {
                if (_identity is not null)
                {
                    _identity.Text = text;
                }
            });
        }

        private void Line(string text)
        {
            Console.WriteLine(LogTag + ": " + text);

            // The transcript is written from the Task.Run worker in Start and
            // read to fill the text view on the main thread. StringBuilder is
            // not thread-safe, and an AppendLine racing a ToString corrupts the
            // chunk chain mid-read: the app died on the very first action with
            // ArgumentOutOfRangeException from StringBuilder.ToString. So the
            // append and the snapshot happen together under a lock, and only the
            // finished immutable string ever crosses to the UI thread.
            string snapshot;
            lock (_transcriptLock)
            {
                _transcript.AppendLine(text);
                snapshot = _transcript.ToString();
            }

            BeginInvokeOnMainThread(() =>
            {
                if (_output is not null)
                {
                    _output.Text = snapshot;
                }
            });
        }
    }
}
