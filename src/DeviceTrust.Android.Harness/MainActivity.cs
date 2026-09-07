using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.Graphics;
using Android.OS;
using Android.Views;
using Android.Widget;
using DeviceTrust.Client;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Maui.Android;
using DeviceTrust.Client.Protocol;
using DeviceTrust.Client.Storage;

namespace DeviceTrust.Android.Harness
{
    /// <summary>
    /// On-device harness for the DESIGN.md 25.11 battery, with a button per test.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There are two ways to drive this, and both matter. The buttons are for the
    /// person holding the phone, who needs to press one thing and read a verdict;
    /// the intent extras are for scripted runs, which need to be reproducible and
    /// quotable in a validation record:
    /// </para>
    /// <code>
    /// adb shell am start -n com.example.devicefingerprinting_dotnet/.MainActivity \
    ///   -e action scan -e api_base_url https://host
    /// adb logcat -s DTHARNESS
    /// </code>
    /// <para>
    /// Every result is written to logcat under <c>DTHARNESS</c> as well as to the
    /// screen, so a button press and a scripted run leave the same evidence.
    /// </para>
    /// <para>
    /// The endpoint has no default. A harness that fell back to a baked-in host
    /// would be the one thing this project refuses everywhere else.
    /// </para>
    /// </remarks>
    [Activity(
        Name = "com.example.devicefingerprinting_dotnet.MainActivity",
        Label = "DeviceFingerprinting .NET",
        MainLauncher = true,
        Exported = true,
        LaunchMode = global::Android.Content.PM.LaunchMode.SingleTop)]
    public sealed class MainActivity : Activity
    {
        private const string Tag = "DTHARNESS";

#if HOOKTEST
        static MainActivity()
        {
            // Battery item 14 build only. Loading the gadget here, before any
            // managed work, gives it the earliest point at which it can take
            // over the process. It listens on 127.0.0.1:27042 and resumes
            // immediately, so the hook is placed afterwards over an adb-forwarded
            // session -- deferred deliberately, because at gadget-load time the
            // target libraries are not yet mapped.
            try
            {
                // "helper", not "frida-gadget": the library is renamed so that
                // /proc/self/maps token scanning cannot see it. Only the
                // structural probes should be able to catch what it does.
                Java.Lang.JavaSystem.LoadLibrary("helper");
                global::Android.Util.Log.Info(Tag, "HOOKTEST build: renamed gadget loaded");
            }
            catch (Exception error)
            {
                global::Android.Util.Log.Info(Tag, "HOOKTEST build: gadget load failed " + error.Message);
            }
        }
#endif
        private const string Preferences = "devicetrust.harness";

        private readonly StringBuilder _transcript = new StringBuilder();
        private readonly List<Button> _buttons = new List<Button>();

        private EditText? _baseUrl;
        private EditText? _handle;
        private EditText? _password;
        private EditText? _stolenAccess;
        private EditText? _stolenRefresh;
        private EditText? _victimInstallation;
        private TextView? _status;
        private TextView? _identityView;
        private TextView? _result;
        private bool _busy;

        /// <inheritdoc />
        protected override void OnCreate(Bundle? savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            BuildUserInterface();
            RunIntent(Intent);
        }

        /// <inheritdoc />
        protected override void OnNewIntent(Intent? intent)
        {
            base.OnNewIntent(intent);
            RunIntent(intent);
        }

        // ---------------------------------------------------------------- UI

        private void BuildUserInterface()
        {
            var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
            root.SetPadding(24, 24, 24, 24);

            _status = Heading("Not started");
            root.AddView(_status);

            root.AddView(SectionLabel("Endpoint"));
            _baseUrl = Field("https://<host>.nip.io", GetPreference("api_base_url", string.Empty));
            root.AddView(_baseUrl);

            root.AddView(SectionLabel("Installation and device record"));
            _identityView = Body("No identity loaded yet.");
            root.AddView(_identityView);

            root.AddView(Button("Enrol + native integrity scan", () => RunAsync("scan", ScanAsync)));
            root.AddView(Button("Show installation key", () => RunLocalAsync("keyinfo", KeyInfoLocalAsync)));
            root.AddView(Button("Dump executable mappings", () => RunLocalAsync("mapsdump", MapsDumpAsync)));

            root.AddView(SectionLabel("Account"));
            _handle = Field("handle", GetPreference("handle", "huawei-net"));
            root.AddView(_handle);
            _password = Field("password", GetPreference("password", "Passw0rd123"));
            root.AddView(_password);
            root.AddView(Button("Create account", () => RunAsync("account-register", client => AccountAsync(client, "register"))));
            root.AddView(Button("Log in", () => RunAsync("account-login", client => AccountAsync(client, "login"))));
            root.AddView(Button("Evaluate current account risk", () => RunAsync("policy", PolicyAsync)));

            root.AddView(SectionLabel("Proof of possession"));
            root.AddView(Button("Test protected access", () => RunAsync("bound-access", BoundAccessAsync)));
            root.AddView(Button("Test bound refresh", () => RunAsync("bound-refresh", BoundRefreshAsync)));

            root.AddView(SectionLabel("Access-proof boundary tests (items 5-8)"));
            root.AddView(Button("1. Test replay", () => RunAsync("replay", ReplayAsync)));
            root.AddView(Button("2. Test body tampering", () => RunAsync("body", BodyTamperAsync)));
            root.AddView(Button("3. Test path + method", () => RunAsync("pathmethod", PathMethodAsync)));
            root.AddView(Button("4. Test stale timestamp", () => RunAsync("stale", StaleTimestampAsync)));
            root.AddView(Button("Run all four in sequence", () => RunAsync("boundary", BoundaryAllAsync)));

            root.AddView(SectionLabel("Cross-device tests (items 3-4)"));
            root.AddView(Body(
                "Mint on one phone, then paste the values into the other phone and attempt the "
                + "replay there. A token minted here is refused there because the signature cannot "
                + "be produced without this phone's key."));
            root.AddView(Button("Mint + show my DEVICE token (works under enforce)",
                () => RunAsync("mint-device-token", MintDeviceTokenAsync)));
            root.AddView(Button("Mint + show my account tokens (test only)", () => RunAsync("stolen-mint", StolenMintAsync)));
            _victimInstallation = Field("victim installation_id", string.Empty);
            root.AddView(_victimInstallation);
            _stolenAccess = Field("stolen access token", string.Empty);
            root.AddView(_stolenAccess);
            _stolenRefresh = Field("stolen refresh token", string.Empty);
            root.AddView(_stolenRefresh);
            root.AddView(Button("Attempt stolen DEVICE token", () => RunAsync("steal-device-token", StealDeviceTokenAsync)));
            root.AddView(Button("Attempt stolen protected request", () => RunAsync("stolen-access", StolenAccessAsync)));
            root.AddView(Button("Attempt stolen refresh", () => RunAsync("stolen-refresh", StolenRefreshAsync)));

            root.AddView(SectionLabel("Local state"));
            root.AddView(Button("Clear local account tokens", () => RunAsync("clear-session", ClearSessionAsync)));
            root.AddView(Button("Simulate fresh installation (delete key)", () => RunLocalAsync("reset", ResetLocalAsync)));

            root.AddView(SectionLabel("Result"));
            _result = new TextView(this) { Text = "-", TextSize = 10f };
            _result.SetTypeface(Typeface.Monospace, TypefaceStyle.Normal);
            _result.SetPadding(0, 8, 0, 24);
            root.AddView(_result);

            var scroll = new ScrollView(this);
            scroll.AddView(root);
            SetContentView(scroll);
        }

        private TextView Heading(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 16f };
            view.SetTypeface(Typeface.Default, TypefaceStyle.Bold);
            view.SetPadding(0, 0, 0, 12);
            return view;
        }

        private TextView SectionLabel(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 13f };
            view.SetTypeface(Typeface.Default, TypefaceStyle.Bold);
            view.SetPadding(0, 24, 0, 6);
            return view;
        }

        private TextView Body(string text)
        {
            var view = new TextView(this) { Text = text, TextSize = 11f };
            view.SetPadding(0, 0, 0, 6);
            return view;
        }

        private EditText Field(string hint, string value)
        {
            var view = new EditText(this) { Hint = hint, Text = value, TextSize = 11f };
            view.SetSingleLine(true);
            return view;
        }

        private Button Button(string label, Action onClick)
        {
            var button = new Button(this) { Text = label, TextSize = 12f };
            button.SetAllCaps(false);
            button.Click += (_, _) => onClick();
            _buttons.Add(button);
            return button;
        }

        // ----------------------------------------------------------- plumbing

        private void RunIntent(Intent? intent)
        {
            var action = intent?.GetStringExtra("action");
            var url = intent?.GetStringExtra("api_base_url");
            if (!string.IsNullOrEmpty(url) && _baseUrl is not null)
            {
                _baseUrl.Text = url;
                SetPreference("api_base_url", url!);
            }

            CopyExtra(intent, "handle", _handle);
            CopyExtra(intent, "password", _password);
            CopyExtra(intent, "victim_installation_id", _victimInstallation);
            CopyExtra(intent, "stolen_access_token", _stolenAccess);
            CopyExtra(intent, "stolen_refresh_token", _stolenRefresh);

            if (string.IsNullOrEmpty(action))
            {
                return;
            }

            switch (action)
            {
                case "scan":
                case "enroll": RunAsync("scan", ScanAsync); break;
                case "keyinfo": RunLocalAsync("keyinfo", KeyInfoLocalAsync); break;
                case "account": RunAsync("account", c => AccountAsync(c, intent!.GetStringExtra("mode") ?? "register")); break;
                case "boundary": RunAsync("boundary", BoundaryAllAsync); break;
                case "bound-access": RunAsync("bound-access", BoundAccessAsync); break;
                case "bound-refresh": RunAsync("bound-refresh", BoundRefreshAsync); break;
                case "stolen-mint": RunAsync("stolen-mint", StolenMintAsync); break;
                case "mint-device-token": RunAsync("mint-device-token", MintDeviceTokenAsync); break;
                case "steal-device-token": RunAsync("steal-device-token", StealDeviceTokenAsync); break;
                case "stolen-access": RunAsync("stolen-access", StolenAccessAsync); break;
                case "stolen-refresh": RunAsync("stolen-refresh", StolenRefreshAsync); break;
                case "policy": RunAsync("policy", PolicyAsync); break;
                case "clear-session": RunAsync("clear-session", ClearSessionAsync); break;
                case "reset": RunLocalAsync("reset", ResetLocalAsync); break;
                case "mapsdump": RunLocalAsync("mapsdump", MapsDumpAsync); break;
                default: Line("Unknown action '" + action + "'."); break;
            }
        }

        private void CopyExtra(Intent? intent, string name, EditText? field)
        {
            var value = intent?.GetStringExtra(name);
            if (!string.IsNullOrEmpty(value) && field is not null)
            {
                field.Text = value;
            }
        }

        private void RunAsync(string name, Func<DeviceTrustClient, Task> body)
        {
            if (_busy)
            {
                Toast.MakeText(this, "A test is already running.", ToastLength.Short)?.Show();
                return;
            }

            _busy = true;
            SetButtonsEnabled(false);
            _transcript.Clear();
            Status("Running " + name + "...");
            SetPreference("api_base_url", _baseUrl?.Text ?? string.Empty);
            SetPreference("handle", _handle?.Text ?? string.Empty);
            SetPreference("password", _password?.Text ?? string.Empty);

            var started = DateTimeOffset.UtcNow;
            Task.Run(async () =>
            {
                var ok = true;
                try
                {
                    await WithClientAsync(body).ConfigureAwait(false);
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
                    Line(error.StackTrace ?? string.Empty);
                }
                finally
                {
                    Line("=== DONE action=" + name + " ok=" + (ok ? "1" : "0") + " seconds="
                         + (DateTimeOffset.UtcNow - started).TotalSeconds.ToString("F1", CultureInfo.InvariantCulture)
                         + " ===");
                    RunOnUiThread(() =>
                    {
                        _busy = false;
                        SetButtonsEnabled(true);
                        Status((ok ? "Finished: " : "Failed: ") + name);
                    });
                }
            });
        }

        /// <summary>
        /// Runs an action that touches only this device.
        /// </summary>
        /// <remarks>
        /// Inspecting the key, dumping mappings and deleting the key are local
        /// operations, but they used to be routed through DeviceTrustClient,
        /// whose constructor resolves the endpoint and throws
        /// api_base_url_missing when there is none. A freshly installed phone has
        /// no endpoint yet, so the one screen that could tell you whether the
        /// hardware key exists refused to run. The endpoint rule is right for
        /// anything that talks to a server; it should not gate what does not.
        /// </remarks>
        private void RunLocalAsync(string name, Func<AndroidKeyStoreInstallationKeyStore, string, Task> body)
        {
            if (_busy)
            {
                Toast.MakeText(this, "A test is already running.", ToastLength.Short)?.Show();
                return;
            }

            _busy = true;
            SetButtonsEnabled(false);
            _transcript.Clear();
            Status("Running " + name + "...");

            var started = DateTimeOffset.UtcNow;
            Task.Run(async () =>
            {
                var ok = true;
                try
                {
                    var stateDirectory = System.IO.Path.Combine(FilesDir!.AbsolutePath, "devicetrust");
                    Directory.CreateDirectory(stateDirectory);
                    await body(new AndroidKeyStoreInstallationKeyStore(ApplicationContext!), stateDirectory)
                        .ConfigureAwait(false);
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
                    RunOnUiThread(() =>
                    {
                        _busy = false;
                        SetButtonsEnabled(true);
                        Status((ok ? "Finished: " : "Failed: ") + name);
                    });
                }
            });
        }

        private async Task KeyInfoLocalAsync(AndroidKeyStoreInstallationKeyStore keyStore, string stateDirectory)
        {
            var metadata = await keyStore.GetOrCreateKeyAsync().ConfigureAwait(false);
            Line("key_alias              " + metadata.KeyAlias);
            Line("provider               " + metadata.Provider);
            Line("security_level         " + metadata.SecurityLevel);
            Line("hardware_backed        " + metadata.HardwareBacked);
            Line("private_key_exportable " + metadata.PrivateKeyExportable);
            Line("created_this_run       " + metadata.Created);
            Line("key_thumbprint         " + metadata.PublicKey.Thumbprint);
            Identity("Thumbprint " + metadata.PublicKey.Thumbprint + "\n"
                     + metadata.SecurityLevel + ", hardware_backed=" + metadata.HardwareBacked);
        }

        private async Task ResetLocalAsync(AndroidKeyStoreInstallationKeyStore keyStore, string stateDirectory)
        {
            await keyStore.DeleteKeyAsync().ConfigureAwait(false);
            foreach (var file in Directory.GetFiles(stateDirectory))
            {
                File.Delete(file);
            }

            Line("Installation key deleted and local state cleared.");
            Line("The next enrolment presents a NEW hardware key; the reinstall hint is what");
            Line("correlates it back to this same device.");
        }

        private async Task WithClientAsync(Func<DeviceTrustClient, Task> body)
        {
            var stateDirectory = System.IO.Path.Combine(FilesDir!.AbsolutePath, "devicetrust");
            Directory.CreateDirectory(stateDirectory);

            var keyStore = new AndroidKeyStoreInstallationKeyStore(ApplicationContext!);
            var collector = new AndroidIntegrityCollector(ApplicationContext!);
            var options = new DeviceTrustOptions
            {
                BaseUrl = ReadBaseUrl(),
                NetworkTimeout = TimeSpan.FromSeconds(30),
            };

            using var client = new DeviceTrustClient(
                options,
                keyStore,
                new FileInstallationStateStore(System.IO.Path.Combine(stateDirectory, "state.json")),
                collector);

            await client.RestoreSessionAsync().ConfigureAwait(false);
            await body(client).ConfigureAwait(false);
        }

        private string? ReadBaseUrl()
        {
            var text = _baseUrl?.Text?.Trim();
            return string.IsNullOrEmpty(text) ? null : text;
        }

        // ------------------------------------------------------------ actions

        private async Task KeyInfoAsync(DeviceTrustClient client)
        {
            var identity = await client.LoadIdentityAsync().ConfigureAwait(false);
            Line("installation_id        " + identity.InstallationId);
            Line("key_thumbprint         " + identity.KeyThumbprint);
            Line("provider               " + identity.Key.Provider);
            Line("security_level         " + identity.Key.SecurityLevel);
            Line("hardware_backed        " + identity.Key.HardwareBacked);
            Line("private_key_exportable " + identity.Key.PrivateKeyExportable);
            Line("created_this_run       " + identity.Key.Created);
            Identity("Installation " + identity.InstallationId + "\nThumbprint " + identity.KeyThumbprint
                     + "\n" + identity.Key.SecurityLevel + ", hardware_backed=" + identity.Key.HardwareBacked);
        }

        private async Task ScanAsync(DeviceTrustClient client)
        {
            var registration = await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var identity = await client.LoadIdentityAsync().ConfigureAwait(false);
            Line("installation_id        " + registration.InstallationId);
            Line("device_id              " + registration.DeviceId);
            Line("recognition            " + registration.Method + " / " + registration.Confidence);
            Line("key_thumbprint         " + identity.KeyThumbprint);
            Line("key_created_this_run   " + identity.Key.Created);
            Line("security_level         " + identity.Key.SecurityLevel
                 + "  hardware_backed=" + identity.Key.HardwareBacked);

            var deviceToken = await client.AcquireDeviceTokenAsync().ConfigureAwait(false);

            // The raw bucket numbers are logged before the verdict, because a
            // bucket reporting compared_bytes = 0 is inert rather than clean and
            // that distinction is invisible in the score.
            var measurement = ManagedCodeIntegrity.Measure();
            Line("code_integrity checked=" + measurement.Checked
                 + (measurement.Reason.Length > 0 ? " reason=" + measurement.Reason : string.Empty));
            Line("  core compared=" + measurement.CoreComparedBytes + " diff=" + measurement.CoreDiffBytes
                 + (measurement.CoreComparedBytes == 0 ? "  <-- INERT" : string.Empty));
            Line("  ext  compared=" + measurement.ExtComparedBytes + " diff=" + measurement.ExtDiffBytes
                 + " libs=" + measurement.ExtLibrariesDiffering
                 + (measurement.ExtComparedBytes == 0 ? "  <-- INERT" : string.Empty));
            Line("  app  compared=" + measurement.AppComparedBytes + " diff=" + measurement.AppDiffBytes
                 + " libs=" + measurement.AppLibrariesDiffering
                 + (measurement.AppComparedBytes == 0 ? "  <-- INERT" : string.Empty));
            Line("  diffed_libs=" + (measurement.DiffedLibraries.Length == 0 ? "<none>" : measurement.DiffedLibraries));
            Line("  execute-only regions unlocked=" + measurement.ExecuteOnlyRegionsUnlocked
                 + " unreadable=" + measurement.ExecuteOnlyRegionsUnreadable);

            var decision = await client.SubmitIntegrityReportAsync(deviceToken).ConfigureAwait(false);
            Line("probes " + string.Join(",", client.LastRequiredProbes));
            Line("INTEGRITY score=" + decision.Score.ToString(CultureInfo.InvariantCulture)
                 + " verdict=" + decision.Verdict + " mode=" + decision.Mode);
            foreach (var reason in decision.Reasons)
            {
                Line("  REASON " + reason.Code + " +" + reason.Points.ToString(CultureInfo.InvariantCulture)
                     + (reason.Hard ? " [HARD]" : string.Empty));
            }

            if (decision.Reasons.Count == 0)
            {
                Line("  REASON <none>");
            }

            var summary = await client.GetDeviceSummaryAsync(deviceToken).ConfigureAwait(false);
            Line("installations_on_device " + summary.InstallationCount);
            Identity("Installation " + registration.InstallationId
                     + "\nDevice " + registration.DeviceId
                     + "\nRecognition " + registration.Method + " / " + registration.Confidence
                     + "\nIntegrity " + decision.Score + "/100 " + decision.Verdict
                     + "\nInstallations on device " + summary.InstallationCount);
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
            foreach (var reason in policy.Reasons)
            {
                Line("  " + reason.Code + " +" + reason.Points.ToString(CultureInfo.InvariantCulture));
            }
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

        private async Task ReplayAsync(DeviceTrustClient client)
        {
            var session = RequireSession(client);
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["probe"] = "replay",
            });
            var fixture = await client.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", body, session.AccessToken).ConfigureAwait(false);
            var first = await client.SendAccessProofFixtureAsync(fixture).ConfigureAwait(false);
            if (Json.GetString(first, "access_proof") != "accepted")
            {
                Line("ITEM FAIL  5. replay -- the control request was not accepted");
                return;
            }

            await ItemAsync("5. exact replay", 401, "access_proof_replay",
                () => client.SendAccessProofFixtureAsync(fixture)).ConfigureAwait(false);
        }

        private async Task BodyTamperAsync(DeviceTrustClient client)
        {
            var session = RequireSession(client);
            var signed = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["amount"] = 1,
            });
            var tampered = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["amount"] = 1000000,
            });
            var fixture = await client.BuildAccessProofFixtureAsync(
                "POST", "/v1/account/protected-echo", signed, session.AccessToken).ConfigureAwait(false);
            await ItemAsync("6. body tampering", 401, "access_proof_body_mismatch",
                () => client.SendAccessProofFixtureAsync(fixture, actualBody: tampered)).ConfigureAwait(false);
        }

        private async Task PathMethodAsync(DeviceTrustClient client)
        {
            var session = RequireSession(client);

            var pathFixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/not-the-requested-route", null, session.AccessToken).ConfigureAwait(false);
            await ItemAsync("7a. path tampering", 401, "access_proof_path_mismatch",
                () => client.SendAccessProofFixtureAsync(
                    pathFixture, actualMethod: "GET", actualPath: "/v1/account/me")).ConfigureAwait(false);

            var methodFixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/protected-echo", null, session.AccessToken).ConfigureAwait(false);
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["message"] = "actual POST while the proof says GET",
            });
            await ItemAsync("7b. method tampering", 401, "access_proof_method_mismatch",
                () => client.SendAccessProofFixtureAsync(
                    methodFixture, actualMethod: "POST", actualPath: "/v1/account/protected-echo",
                    actualBody: body)).ConfigureAwait(false);
        }

        private async Task StaleTimestampAsync(DeviceTrustClient client)
        {
            var session = RequireSession(client);
            // The server allows 120 seconds of skew. 180 is equivalent to
            // replaying a captured proof after expiry without idling for two
            // minutes on a phone that must not be disturbed.
            var fixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/me", null, session.AccessToken,
                timestampSeconds: AccessProof.CurrentTimestamp() - 180).ConfigureAwait(false);
            await ItemAsync("8. stale timestamp", 401, "access_proof_timestamp_outside_window",
                () => client.SendAccessProofFixtureAsync(fixture)).ConfigureAwait(false);
        }

        private async Task BoundaryAllAsync(DeviceTrustClient client)
        {
            if (client.Session is null)
            {
                // The button flow expects "Create account" to have been pressed
                // first; a scripted run has no such ordering, so open one here.
                await AccountAsync(client, "register").ConfigureAwait(false);
            }

            // Items 5-8 must run within 10 minutes of a refresh, or an expired
            // access token makes them inconclusive. Rotating first starts that
            // window now rather than whenever the account was opened.
            await client.RefreshAccountSessionAsync().ConfigureAwait(false);
            Line("refreshed -- items 5-8 start inside the 10 minute window");
            await ReplayAsync(client).ConfigureAwait(false);
            await BodyTamperAsync(client).ConfigureAwait(false);
            await PathMethodAsync(client).ConfigureAwait(false);
            await StaleTimestampAsync(client).ConfigureAwait(false);
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
            Line("Paste these into the other phone and press the two 'Attempt stolen' buttons.");
        }

        /// <summary>
        /// Mints a device token and prints it for the other handset to replay.
        /// </summary>
        /// <remarks>
        /// The device token is the useful vehicle for a cross-device test on this
        /// client, because installation challenge/verify does not pass through the
        /// integrity gate. An account access token would be the more faithful
        /// item 3, but a .NET Android client cannot currently obtain one in
        /// enforce mode: the Mono runtime maps writable-and-executable memory,
        /// which scores android_wx_memory +60 and puts every .NET device at
        /// "review". The cryptographic property under test -- a bearer token is
        /// refused when the access proof is signed by a different installation
        /// key -- is identical either way, and this version runs under the
        /// production configuration rather than requiring observe mode.
        /// </remarks>
        private async Task MintDeviceTokenAsync(DeviceTrustClient client)
        {
            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var identity = await client.LoadIdentityAsync().ConfigureAwait(false);
            var deviceToken = await client.AcquireDeviceTokenAsync().ConfigureAwait(false);

            // Prove the token works here before asking the other phone to fail
            // with it, so a rejection there cannot be blamed on a dead token.
            var me = await client.SendProtectedAsync("GET", "/v1/device/me", null, deviceToken)
                .ConfigureAwait(false);
            Line("MINT installation_id    " + identity.InstallationId);
            Line("MINT device_id          " + Json.GetString(me, "device_id"));
            Line("MINT device_token       " + deviceToken);
            Line("This token works on THIS phone. Paste it into the other phone.");
        }

        /// <summary>Replays another handset's device token with this handset's key.</summary>
        private async Task StealDeviceTokenAsync(DeviceTrustClient client)
        {
            var token = (_stolenAccess?.Text ?? string.Empty).Trim();
            var victim = (_victimInstallation?.Text ?? string.Empty).Trim();
            if (token.Length == 0 || victim.Length == 0)
            {
                Line("Paste the other phone's device token and installation id first.");
                return;
            }

            await client.RegisterInstallationAsync(ReadReinstallHint()).ConfigureAwait(false);
            var mine = await client.LoadIdentityAsync().ConfigureAwait(false);
            Line("victim installation " + victim);
            Line("my installation     " + mine.InstallationId);
            Line("my key thumbprint   " + mine.KeyThumbprint);

            var fixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/device/me", null, token, proofInstallationId: victim).ConfigureAwait(false);
            await ItemAsync("3. stolen device token, replayed with this phone's key",
                401, "invalid_installation_signature",
                () => client.SendAccessProofFixtureAsync(fixture)).ConfigureAwait(false);
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
            // this phone's hardware key. Using this phone's own id would fail
            // earlier on an id mismatch and never exercise the signature check
            // that is the actual defence.
            var fixture = await client.BuildAccessProofFixtureAsync(
                "GET", "/v1/account/me", null, token, proofInstallationId: victim).ConfigureAwait(false);
            await ItemAsync("3. stolen access token", 401, "invalid_installation_signature",
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
            await ItemAsync("4. stolen refresh token", 401, "invalid_installation_signature",
                () => client.Api.RefreshAsync(token, challengeId, payload, signature)).ConfigureAwait(false);
        }

        private async Task ClearSessionAsync(DeviceTrustClient client)
        {
            await client.ClearSessionAsync().ConfigureAwait(false);
            Line("Local account tokens cleared. The installation key is untouched.");
        }

        private async Task ResetAsync(DeviceTrustClient client)
        {
            await client.ResetInstallationAsync().ConfigureAwait(false);
            Line("Installation key deleted and local state cleared.");
            Line("The next enrolment presents a NEW hardware key; the reinstall hint is what");
            Line("correlates it back to this same device.");
        }

        /// <summary>
        /// Dumps a summary of this process's executable mappings.
        /// </summary>
        /// <remarks>
        /// Diagnostic only, and it exists because two buckets read
        /// <c>compared_bytes = 0</c> on the first Huawei run. An inert bucket and
        /// a clean one are indistinguishable in the score, so the only way to tell
        /// them apart is to look at what the process actually has mapped.
        /// </remarks>
        /// <summary>
        /// Reports how executable memory is mapped in this process.
        /// </summary>
        /// <remarks>
        /// Written to answer one question with evidence: why does a Flutter
        /// release build score 0 for writable-and-executable memory while a .NET
        /// build scores +60? Both answers are visible in a single .NET process,
        /// because it runs ART and Mono side by side. ART's JIT keeps write and
        /// execute in two separate views of the same pages and never maps them
        /// together; Mono's code manager maps one anonymous region that is
        /// writable and executable at once.
        /// </remarks>
        private Task MapsDumpAsync(AndroidKeyStoreInstallationKeyStore keyStore, string stateDirectory)
        {
            var lines = File.ReadAllLines("/proc/self/maps");
            var wx = new List<string>();
            long wxBytes = 0;
            var wxAnonymous = 0;
            var wxFileBacked = 0;
            var jit = new List<string>();
            var executableGroups = new Dictionary<string, int>(StringComparer.Ordinal);

            foreach (var raw in lines)
            {
                var parts = raw.Split(new[] { ' ' }, 6, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5)
                {
                    continue;
                }

                var bounds = parts[0].Split('-');
                var perms = parts[1];
                var inode = parts[4];
                var path = parts.Length >= 6 ? parts[5].Trim() : string.Empty;
                if (perms.Length < 4 || bounds.Length != 2)
                {
                    continue;
                }

                long size = 0;
                if (ulong.TryParse(bounds[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var from)
                    && ulong.TryParse(bounds[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var to)
                    && to > from)
                {
                    size = (long)(to - from);
                }

                var lower = path.ToLowerInvariant();
                var isJit = lower.Contains("jit-cache", StringComparison.Ordinal)
                            || lower.Contains("jit-zygote", StringComparison.Ordinal)
                            || lower.Contains("dalvik-jit-code-cache", StringComparison.Ordinal);
                if (isJit)
                {
                    jit.Add(perms + "  " + (size / 1024).ToString(CultureInfo.InvariantCulture).PadLeft(6)
                            + " KB  " + path);
                }

                if (perms[1] == 'w' && perms[2] == 'x')
                {
                    wxBytes += size;
                    var anonymous = inode == "0" && path.Length == 0;
                    if (anonymous)
                    {
                        wxAnonymous++;
                    }
                    else
                    {
                        wxFileBacked++;
                    }

                    if (wx.Count < 20)
                    {
                        wx.Add(perms + "  " + (size / 1024).ToString(CultureInfo.InvariantCulture).PadLeft(6)
                               + " KB  " + (anonymous ? "anonymous (no backing file)" : path));
                    }
                }

                if (perms[2] == 'x')
                {
                    var key = perms.Substring(0, 4) + " " + (path.Length == 0 ? "<anonymous>" : path);
                    executableGroups[key] = executableGroups.TryGetValue(key, out var seen) ? seen + 1 : 1;
                }
            }

            Line("maps_total_lines " + lines.Length);
            Line("executable mapping groups " + executableGroups.Count);
            Line(string.Empty);
            Line("--- WRITABLE + EXECUTABLE (what android_wx_memory counts) ---");
            Line("regions=" + (wxAnonymous + wxFileBacked)
                 + "  anonymous=" + wxAnonymous + "  file_backed=" + wxFileBacked
                 + "  total=" + (wxBytes / 1024).ToString(CultureInfo.InvariantCulture) + " KB");
            foreach (var entry in wx)
            {
                Line("  " + entry);
            }

            Line(string.Empty);
            Line("--- ART JIT CODE CACHE (same pages, separate views) ---");
            if (jit.Count == 0)
            {
                Line("  none mapped");
            }
            else
            {
                foreach (var entry in jit)
                {
                    Line("  " + entry);
                }

                Line("  note: ART maps the cache rw- and r-x separately and never rwx.");
            }

            Line(string.Empty);
            Line("--- top executable mapping groups ---");
            foreach (var entry in executableGroups.OrderByDescending(item => item.Value).Take(6))
            {
                Line("  " + entry.Value.ToString(CultureInfo.InvariantCulture).PadLeft(3) + "  " + entry.Key);
            }

            return Task.CompletedTask;
        }

        // ----------------------------------------------------------- helpers

        private async Task ItemAsync(string name, int status, string code, Func<Task> operation)
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

        private static AccountSession RequireSession(DeviceTrustClient client)
        {
            return client.Session ?? throw new DeviceTrustException(
                "Create or log in to an account first.", "account_session_required");
        }

        private ReinstallHint? ReadReinstallHint()
        {
            try
            {
                var androidId = global::Android.Provider.Settings.Secure.GetString(
                    ContentResolver, global::Android.Provider.Settings.Secure.AndroidId);
                return ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", androidId);
            }
            catch (Exception)
            {
                // A missing hint must never stop cryptographic identity; the
                // device simply enrols as new.
                return null;
            }
        }

        private string GetPreference(string key, string fallback)
        {
            return GetSharedPreferences(Preferences, FileCreationMode.Private)?.GetString(key, fallback) ?? fallback;
        }

        private void SetPreference(string key, string value)
        {
            var editor = GetSharedPreferences(Preferences, FileCreationMode.Private)?.Edit();
            editor?.PutString(key, value);
            editor?.Apply();
        }

        private void SetButtonsEnabled(bool enabled)
        {
            foreach (var button in _buttons)
            {
                button.Enabled = enabled;
            }
        }

        private void Status(string text)
        {
            RunOnUiThread(() =>
            {
                if (_status is not null)
                {
                    _status.Text = text;
                }
            });
        }

        private void Identity(string text)
        {
            RunOnUiThread(() =>
            {
                if (_identityView is not null)
                {
                    _identityView.Text = text;
                }
            });
        }

        private void Line(string text)
        {
            global::Android.Util.Log.Info(Tag, text);
            _transcript.AppendLine(text);
            RunOnUiThread(() =>
            {
                if (_result is not null)
                {
                    _result.Text = _transcript.ToString();
                }
            });
        }
    }
}
