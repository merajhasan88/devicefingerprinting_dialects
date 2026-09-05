using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Cli.Harness;
using DeviceTrust.Client;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Protocol;

namespace DeviceTrust.Cli
{
    /// <summary>
    /// The console harness: a working example of the SDK and the instrument that
    /// proves this client against a live server.
    /// </summary>
    internal static class Program
    {
        private static async Task<int> Main(string[] rawArguments)
        {
            var (command, positional, switches) = ParseArguments(rawArguments);
            if (command is null or "help" or "--help" or "-h")
            {
                PrintUsage();
                return command is null ? 1 : 0;
            }

            var configuration = HarnessConfiguration.Resolve(switches);
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            try
            {
                return await DispatchAsync(command, positional, configuration, cancellation.Token)
                    .ConfigureAwait(false);
            }
            catch (DeviceTrustConfigurationException error)
            {
                Console.Error.WriteLine("Configuration error: " + error.Message + " [" + error.Code + "]");
                return 2;
            }
            catch (DeviceTrustApiException error)
            {
                Console.Error.WriteLine(
                    "Server rejected the request: " + error.Message
                    + " [" + (error.Code ?? "no code") + "] HTTP "
                    + error.StatusCode.ToString(CultureInfo.InvariantCulture));
                return 3;
            }
            catch (DeviceTrustException error)
            {
                Console.Error.WriteLine("Client error: " + error);
                return 4;
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Cancelled.");
                return 130;
            }
        }

        private static async Task<int> DispatchAsync(
            string command,
            IReadOnlyList<string> positional,
            HarnessConfiguration configuration,
            CancellationToken cancellationToken)
        {
            switch (command)
            {
                case "health":
                    return await HealthAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "keyinfo":
                    return await KeyInfoAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "enroll":
                case "bootstrap":
                    return await EnrollAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "account":
                    return await AccountAsync(positional, configuration, cancellationToken).ConfigureAwait(false);
                case "me":
                    return await AccountMeAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "echo":
                    return await EchoAsync(positional, configuration, cancellationToken).ConfigureAwait(false);
                case "policy":
                    return await PolicyAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "device":
                    return await DeviceAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "refresh":
                    return await RefreshAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "scan":
                    return await ScanAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "reset":
                    return await ResetAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "conformance":
                    return await ConformanceAsync(configuration, cancellationToken).ConfigureAwait(false);
                case "battery":
                    return await BatteryAsync(configuration, cancellationToken).ConfigureAwait(false);
                default:
                    Console.Error.WriteLine("Unknown command '" + command + "'.");
                    PrintUsage();
                    return 1;
            }
        }

        private static async Task<int> HealthAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var api = new DeviceTrustApi(configuration.ToClientOptions());
            var ready = await api.HealthReadyAsync(cancellationToken).ConfigureAwait(false);

            Report.Heading("Server");
            Report.Field("Endpoint", api.BaseUri.ToString());
            Report.Field("Status", Json.GetString(ready, "status"));
            var database = Json.GetObject(ready, "database");
            if (database is not null)
            {
                Report.Field("Database engine", Json.GetString(database.Value, "engine"));
                Report.Field("Database version", Json.GetString(database.Value, "version"));
                Report.Field("Minimum supported", Json.GetString(database.Value, "minimum_supported"));
                Report.Field("Supported", Json.GetBoolean(database.Value, "supported") ? "yes" : "no");
            }

            Report.Field("Integrity mode", Json.GetString(ready, "integrity_mode"));
            Report.Field("Integrity freshness", Json.GetInt32(ready, "integrity_freshness_seconds") + " s");
            Report.Field("Device policy mode", Json.GetString(ready, "device_policy_mode"));
            Report.Field("Remote attestation", Json.GetString(ready, "remote_attestation"));
            var redis = Json.GetObject(ready, "redis");
            if (redis is not null)
            {
                Report.Field("Nonce backend", Json.GetString(redis.Value, "nonce_backend"));
                Report.Field("Rate limiting", Json.GetBoolean(redis.Value, "rate_limiting") ? "on" : "off");
            }

            return 0;
        }

        private static async Task<int> KeyInfoAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            var identity = await client.LoadIdentityAsync(cancellationToken).ConfigureAwait(false);

            Report.Heading("Installation key");
            Report.Field("Installation id", identity.InstallationId);
            Report.Field("Key thumbprint", identity.KeyThumbprint);
            Report.Field("Algorithm", identity.Key.Algorithm);
            Report.Field("Signature encoding", identity.Key.SignatureFormat);
            Report.Field("Provider", identity.Key.Provider);
            Report.Field("Key alias", identity.Key.KeyAlias);
            Report.Field("Security level", identity.Key.SecurityLevel);
            Report.Field("Hardware-backed", identity.Key.HardwareBacked ? "yes" : "no");
            Report.Field("Private key exportable", identity.Key.PrivateKeyExportable ? "yes" : "no");
            Report.Field("Created this run", identity.Key.Created ? "yes" : "no");
            Report.Field("Remote key attestation", "not used, by design");

            if (!identity.Key.HardwareBacked)
            {
                Report.Warn(
                    "This key is not hardware-backed. It proves the protocol, not device binding. "
                    + "Use the AndroidKeyStore, Secure Enclave or CNG store for any security claim.");
            }

            return 0;
        }

        private static async Task<int> EnrollAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var collector = BuildCollector(configuration);
            var client = context.CreatePersistentDevice(collector);
            WarnAboutFixtures(collector);

            await client.BootstrapAsync(ReadReinstallHint(configuration), cancellationToken).ConfigureAwait(false);

            Report.Heading("Installation and device record");
            var record = client.DeviceRecord!;
            Report.Field("Installation id", record.InstallationId);
            Report.Field("Device id", record.DeviceId);
            Report.Field("Platform", record.Platform);
            Report.Field("Key thumbprint", record.KeyThumbprint);
            Report.Field("Recognition", record.Method + " / " + record.Confidence);
            Report.Field("Known installations", record.InstallationCount);
            Report.Field("Linked accounts", record.LinkedAccountCount);
            Report.Field("Device status", record.DeviceStatus);
            Report.Field("Last seen", record.LastSeenAt);

            PrintIntegrity(client.LatestIntegrity, client.LastRequiredProbes);
            PrintPolicy(record.Policy);
            return 0;
        }

        private static async Task<int> AccountAsync(
            IReadOnlyList<string> positional,
            HarnessConfiguration configuration,
            CancellationToken cancellationToken)
        {
            var action = positional.Count > 0 ? positional[0] : null;
            if (action is not ("register" or "login"))
            {
                Console.Error.WriteLine("Usage: devicetrust account register|login --handle <handle> --password <password>");
                return 1;
            }

            var switches = ParseArguments(positional.Skip(1).ToArray()).Switches;
            if (!switches.TryGetValue("handle", out var handle) || string.IsNullOrWhiteSpace(handle)
                || !switches.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
            {
                Console.Error.WriteLine("Both --handle and --password are required.");
                return 1;
            }

            using var context = new HarnessContext(configuration);
            var collector = BuildCollector(configuration);
            var client = context.CreatePersistentDevice(collector);
            WarnAboutFixtures(collector);

            await client.RegisterInstallationAsync(ReadReinstallHint(configuration), cancellationToken)
                .ConfigureAwait(false);

            var session = action == "register"
                ? await client.RegisterAccountAsync(handle, password, cancellationToken).ConfigureAwait(false)
                : await client.LoginAccountAsync(handle, password, cancellationToken).ConfigureAwait(false);

            Report.Heading(action == "register" ? "Account created" : "Account authenticated");
            Report.Field("Account id", session.AccountId);
            Report.Field("Access token", Abbreviate(session.AccessToken));
            Report.Field("Refresh token", Abbreviate(session.RefreshToken));
            PrintIntegrity(client.LatestIntegrity, client.LastRequiredProbes);
            PrintPolicy(session.Policy);
            return 0;
        }

        private static async Task<int> AccountMeAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            await RequireSessionAsync(client, cancellationToken).ConfigureAwait(false);

            var me = await client.GetAccountMeAsync(cancellationToken).ConfigureAwait(false);
            Report.Heading("GET /v1/account/me");
            Report.Field("Account id", Json.GetString(me, "account_id"));
            Report.Field("Device id", Json.GetString(me, "device_id"));
            Report.Field("Installation id", Json.GetString(me, "installation_id"));
            Report.Field("Session id", Json.GetString(me, "session_id"));
            Report.Field("Access proof", Json.GetString(me, "access_proof"));
            return 0;
        }

        private static async Task<int> EchoAsync(
            IReadOnlyList<string> positional,
            HarnessConfiguration configuration,
            CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            await RequireSessionAsync(client, cancellationToken).ConfigureAwait(false);

            var message = positional.Count > 0 ? string.Join(' ', positional) : "proof-of-possession body binding test";
            var probeId = Guid.NewGuid().ToString();
            var response = await client.ProtectedEchoAsync(
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["probe_id"] = probeId,
                    ["message"] = message,
                },
                cancellationToken).ConfigureAwait(false);

            Report.Heading("POST /v1/account/protected-echo");
            Report.Field("Access proof", Json.GetString(response, "access_proof"));
            Report.Field("Server body SHA-256", Json.GetString(response, "body_sha256"));
            var echoed = Json.GetObject(response, "echo");
            Report.Field(
                "Body round-tripped",
                echoed is not null && Json.GetString(echoed.Value, "probe_id") == probeId ? "yes" : "no");
            return 0;
        }

        private static async Task<int> PolicyAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            await RequireSessionAsync(client, cancellationToken).ConfigureAwait(false);

            PrintPolicy(await client.GetPolicyAsync(cancellationToken).ConfigureAwait(false));
            return 0;
        }

        private static async Task<int> DeviceAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            var token = await client.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            var record = await client.GetDeviceSummaryAsync(token, cancellationToken).ConfigureAwait(false);

            Report.Heading("GET /v1/device/me");
            Report.Field("Installation id", record.InstallationId);
            Report.Field("Device id", record.DeviceId);
            Report.Field("Platform", record.Platform);
            Report.Field("Recognition", record.Method + " / " + record.Confidence);
            Report.Field("Known installations", record.InstallationCount);
            Report.Field("Linked accounts", record.LinkedAccountCount);
            Report.Field("Created", record.CreatedAt);
            Report.Field("Last seen", record.LastSeenAt);
            PrintPolicy(record.Policy);
            return 0;
        }

        private static async Task<int> RefreshAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            await RequireSessionAsync(client, cancellationToken).ConfigureAwait(false);

            var rotated = await client.RefreshAccountSessionAsync(cancellationToken).ConfigureAwait(false);
            Report.Heading("Refresh rotation");
            Report.Field("Account id", rotated.AccountId);
            Report.Field("New access token", Abbreviate(rotated.AccessToken));
            Report.Field("New refresh token", Abbreviate(rotated.RefreshToken));
            Report.Line("The previous refresh token is now revoked; reusing it revokes the whole family.");
            return 0;
        }

        private static async Task<int> ScanAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var collector = BuildCollector(configuration);
            if (collector is null)
            {
                Console.Error.WriteLine("No integrity collector is configured; nothing to scan.");
                return 1;
            }

            var client = context.CreatePersistentDevice(collector);
            WarnAboutFixtures(collector);

            var token = await client.AcquireDeviceTokenAsync(cancellationToken).ConfigureAwait(false);
            var decision = await client.SubmitIntegrityReportAsync(token, cancellationToken).ConfigureAwait(false);
            PrintIntegrity(decision, client.LastRequiredProbes);
            return 0;
        }

        private static async Task<int> ResetAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            using var context = new HarnessContext(configuration);
            var client = context.CreatePersistentDevice(BuildCollector(configuration));
            await client.ResetInstallationAsync(cancellationToken).ConfigureAwait(false);
            Report.Heading("Local installation reset");
            Report.Line("The installation key and local state are gone. The next run enrols as a new");
            Report.Line("installation; the reinstall hint is what correlates it back to this device.");
            return 0;
        }

        private static async Task<int> ConformanceAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            var mode = await PrintTargetAsync(configuration, cancellationToken).ConfigureAwait(false);
            using var context = new HarnessContext(configuration);
            return await new ClientConformanceSuite(context, mode).RunAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task<int> BatteryAsync(HarnessConfiguration configuration, CancellationToken cancellationToken)
        {
            var mode = await PrintTargetAsync(configuration, cancellationToken).ConfigureAwait(false);
            using var context = new HarnessContext(configuration);
            return await new AccessProofBattery(context, mode).RunAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task<string> PrintTargetAsync(
            HarnessConfiguration configuration,
            CancellationToken cancellationToken)
        {
            using var api = new DeviceTrustApi(configuration.ToClientOptions());
            var ready = await api.HealthReadyAsync(cancellationToken).ConfigureAwait(false);
            var database = Json.GetObject(ready, "database");
            var mode = Json.GetString(ready, "integrity_mode") ?? "observe";

            Console.WriteLine("target   : " + api.BaseUri);
            Console.WriteLine("database : "
                              + (database is null ? "unknown" : Json.GetString(database.Value, "engine") + " "
                                  + Json.GetString(database.Value, "version")));
            Console.WriteLine("integrity: " + mode);
            Console.WriteLine("client   : DeviceTrust.Client (.NET) on " + Environment.OSVersion.Platform
                              + ", " + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
            Console.WriteLine();
            Report.Warn(
                "Integrity measurements in this run are harness fixtures, not device readings. "
                + "They exercise the server's scoring and this client's report path; they are not evidence "
                + "about any real device.");
            Console.WriteLine();
            return mode;
        }

        private static IIntegrityProbeCollector? BuildCollector(HarnessConfiguration configuration)
        {
            return configuration.IntegrityCollector switch
            {
                "none" => null,
                "native" => throw new DeviceTrustConfigurationException(
                    "No native collector is compiled into this console build. Native collection lives in "
                    + "DeviceTrust.Client.Maui (Android/iOS) and DeviceTrust.Client.Windows.",
                    "native_collector_unavailable"),
                _ => new ConformanceProbeCollector(),
            };
        }

        private static void WarnAboutFixtures(IIntegrityProbeCollector? collector)
        {
            if (collector is ConformanceProbeCollector)
            {
                Report.Warn(
                    "Using harness integrity fixtures. Every probe value below is synthetic; nothing was "
                    + "measured on this machine.");
            }
        }

        private static ReinstallHint? ReadReinstallHint(HarnessConfiguration configuration)
        {
            // A desktop harness has no Android ID or IDFV. Deriving one from the
            // state directory keeps repeat runs on this machine correlating to a
            // single device record, which is what makes the recognition output
            // meaningful, without pretending to be a platform identifier.
            return ReinstallHint.FromRawIdentifier(
                "android_id_sha256",
                "dotnet_harness_state_dir",
                Path.GetFullPath(configuration.StateDirectory));
        }

        private static async Task RequireSessionAsync(DeviceTrustClient client, CancellationToken cancellationToken)
        {
            var session = await client.RestoreSessionAsync(cancellationToken).ConfigureAwait(false);
            if (session is null)
            {
                throw new DeviceTrustException(
                    "No stored account session. Run 'devicetrust account register' or 'account login' first.",
                    "account_session_required");
            }
        }

        private static void PrintIntegrity(IntegrityDecision? decision, IReadOnlyList<string> probes)
        {
            if (decision is null)
            {
                return;
            }

            Report.Heading("Integrity decision");
            Report.Field("Mode", decision.Mode);
            Report.Field("Score", decision.Score.ToString(CultureInfo.InvariantCulture) + "/100");
            Report.Field("Verdict", decision.Verdict);
            Report.Field("Hard block", decision.HardBlock ? "yes" : "no");
            Report.Field("Report id", decision.ReportId);
            Report.Field("Fresh for", decision.FreshForSeconds + " s");
            Report.Field("Remote attestation", decision.RemoteAttestation);
            Report.Field("Probes requested", Report.Join(probes));
            if (decision.Reasons.Count == 0)
            {
                Report.Line("No integrity-risk signals were scored.");
                return;
            }

            foreach (var reason in decision.Reasons)
            {
                Report.Line(reason.Code + " (+" + reason.Points.ToString(CultureInfo.InvariantCulture) + ")"
                            + (reason.Hard ? " [HARD]" : string.Empty) + ": " + reason.Message);
            }
        }

        private static void PrintPolicy(RiskPolicyDecision? policy)
        {
            if (policy is null)
            {
                return;
            }

            Report.Heading("Relationship-risk policy");
            Report.Field("Mode", policy.Mode);
            Report.Field("Event", policy.EventType);
            Report.Field("Score", policy.Score);
            Report.Field("Recommended", policy.RecommendedAction);
            Report.Field("Effective", policy.EffectiveAction);
            Report.Field("Enforced", policy.Enforced ? "yes" : "no");
            foreach (var reason in policy.Reasons)
            {
                Report.Line(reason.Code + " (+" + reason.Points.ToString(CultureInfo.InvariantCulture) + "): "
                            + reason.Message);
            }
        }

        private static string Abbreviate(string token)
        {
            return token.Length <= 24 ? token : token.Substring(0, 12) + "..." + token.Substring(token.Length - 8);
        }

        private static (string? Command, IReadOnlyList<string> Positional, IReadOnlyDictionary<string, string> Switches)
            ParseArguments(string[] arguments)
        {
            string? command = null;
            var positional = new List<string>();
            var switches = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            for (var index = 0; index < arguments.Length; index++)
            {
                var argument = arguments[index];
                if (argument.StartsWith("--", StringComparison.Ordinal))
                {
                    var name = argument.Substring(2);
                    var separator = name.IndexOf('=');
                    if (separator >= 0)
                    {
                        switches[name.Substring(0, separator)] = name.Substring(separator + 1);
                        continue;
                    }

                    if (index + 1 < arguments.Length && !arguments[index + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        switches[name] = arguments[++index];
                    }
                    else
                    {
                        switches[name] = "true";
                    }

                    continue;
                }

                if (command is null)
                {
                    command = argument;
                }
                else
                {
                    positional.Add(argument);
                }
            }

            return (command, positional, switches);
        }

        private static void PrintUsage()
        {
            Console.WriteLine(@"devicetrust - console harness for the Device Trust .NET client SDK

USAGE
  devicetrust <command> [options]

COMMANDS
  health                    Read /health/ready: engine, version, integrity mode, Redis
  keyinfo                   Show the local installation key and what backs it
  enroll                    Register, prove possession, report integrity, read the device record
  scan                      Run one server-challenged integrity round trip
  account register          Open an account   --handle <h> --password <p>
  account login             Authenticate      --handle <h> --password <p>
  me                        GET  /v1/account/me with an access proof
  echo [message]            POST /v1/account/protected-echo with an access proof
  policy                    GET  /v1/policy/me
  device                    GET  /v1/device/me
  refresh                   Rotate the refresh session with a signed challenge
  reset                     Delete the local key and state, so the next run enrols fresh
  conformance               Prove this .NET client against a live server
  battery                   The DESIGN.md 25.11 battery, between two simulated devices

OPTIONS
  --base-url <url>          The API endpoint. No default: a run without one fails
                            with api_base_url_missing. Also read from API_BASE_URL.
  --state-dir <path>        Where the key and local state live (DEVICETRUST_STATE_DIR)
  --collector <name>        fixture (default) | none | native
  --stolen-access-token <t> A foreign access token for boundary testing
  --stolen-refresh-token <t> A foreign refresh token for boundary testing
  --verbose                 Print more detail

NOTES
  The console build uses a software key and harness integrity fixtures. It proves
  the wire protocol; it proves nothing about device binding or the state of any
  real device. Use the AndroidKeyStore, Secure Enclave or CNG key stores, and the
  native collectors, for anything that makes a security claim.");
        }
    }
}
