using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>
    /// Synthetic Android probe measurements for exercising the server's scoring
    /// table and the .NET client's report path from a desktop machine.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>These are fixtures, not measurements.</b> Nothing here was read from a
    /// device. This collector is the direct .NET counterpart of
    /// <c>clean_probes()</c> in the Python <c>conformance_suite.py</c>, and it
    /// exists for the same two reasons: the server's scoring rules are testable
    /// without a phone, and the .NET client's challenge/collect/sign/submit round
    /// trip is testable without one either.
    /// </para>
    /// <para>
    /// The distinction that matters: a <i>client SDK</i> must never fabricate
    /// probe results to get past the integrity gate — that would defeat the
    /// entire mechanism. A <i>conformance harness</i> may submit crafted
    /// measurements precisely because its purpose is to check how the server
    /// scores a given input. Every report this collector produces is labelled
    /// with <c>harness_fixture</c> so a stored report can never be mistaken for a
    /// real device reading, and the CLI prints a warning on every run that uses
    /// it.
    /// </para>
    /// <para>
    /// The signing certificate digest matches the one the Python suite uses, so a
    /// server configured to run that suite — <c>INTEGRITY_ANDROID_CERT_SHA256</c>
    /// set to this value, or empty to disable the allow-list — accepts this
    /// harness too, with no extra configuration.
    /// </para>
    /// </remarks>
    public sealed class ConformanceProbeCollector : IIntegrityProbeCollector
    {
        /// <summary>The label written into every probe this collector produces.</summary>
        public const string FixtureLabel = "harness_fixture";

        private readonly Dictionary<string, Action<Dictionary<string, ProbeResult>>> _mutations =
            new Dictionary<string, Action<Dictionary<string, ProbeResult>>>(StringComparer.Ordinal);

        /// <summary>Creates a collector that reports a pristine production Android device.</summary>
        public ConformanceProbeCollector()
        {
        }

        /// <summary>
        /// The certificate digest the Python conformance suite presents, so both
        /// harnesses are trusted or rejected by the same server setting.
        /// </summary>
        public static string ConformanceCertificateSha256 { get; } =
            Hex.Sha256Hex(Encoding.UTF8.GetBytes("device-recognition conformance signing certificate"));

        /// <inheritdoc />
        public string Platform => "android";

        /// <inheritdoc />
        public int CollectorVersion => 1;

        /// <summary>The certificate digest this collector will present.</summary>
        public string CertificateSha256 { get; set; } = ConformanceCertificateSha256;

        /// <summary>
        /// Registers a named alteration to the clean fixture, so a scoring rule
        /// can be driven deliberately. The name is recorded in the report.
        /// </summary>
        public ConformanceProbeCollector WithScenario(
            string name,
            Action<Dictionary<string, ProbeResult>> mutation)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A scenario name is required.", nameof(name));
            }

            _mutations[name] = mutation ?? throw new ArgumentNullException(nameof(mutation));
            return this;
        }

        /// <summary>Removes every registered scenario, returning to the clean baseline.</summary>
        public ConformanceProbeCollector ClearScenarios()
        {
            _mutations.Clear();
            return this;
        }

        /// <inheritdoc />
        public Task<IntegrityCollection> CollectAsync(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            CancellationToken cancellationToken = default)
        {
            if (requiredProbes is null)
            {
                throw new ArgumentNullException(nameof(requiredProbes));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var everything = BuildCleanFixture(CertificateSha256);
            var probes = new Dictionary<string, ProbeResult>(StringComparer.Ordinal);
            foreach (var name in requiredProbes)
            {
                if (everything.TryGetValue(name, out var probe))
                {
                    probes[name] = probe;
                }
                else
                {
                    // An unknown probe name is reported honestly rather than
                    // silently dropped: omitting a server-requested probe is
                    // rejected outright, and the server should see that this
                    // collector could not run it.
                    probes[name] = ProbeResult.Unsupported("The harness fixture has no value for '" + name + "'.");
                }
            }

            foreach (var mutation in _mutations)
            {
                mutation.Value(probes);
            }

            return Task.FromResult(new IntegrityCollection(Platform, CollectorVersion, challengeNonce, probes));
        }

        /// <summary>
        /// Builds the pristine baseline: every scoring rule in the server's
        /// Android table should contribute zero points to this.
        /// </summary>
        public static Dictionary<string, ProbeResult> BuildCleanFixture(string certificateSha256)
        {
            var apkHash = Hex.Sha256Hex(Encoding.UTF8.GetBytes("devicetrust-dotnet-harness-apk"));

            return new Dictionary<string, ProbeResult>(StringComparer.Ordinal)
            {
                ["app_identity"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("package_name", "com.example.devicefingerprinting")
                    .With("version_name", "1.0.0")
                    .With("version_code", 1)
                    .With("debuggable", false)
                    .With("allow_backup", false)
                    .With("cert_sha256", new List<string> { certificateSha256 })
                    .With("apk_sha256", apkHash)
                    .With("installer_package", "com.android.vending")
                    .With("source_dir", "/data/app/com.example.devicefingerprinting/base.apk"),

                ["debug_state"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("debugger_connected", false)
                    .With("waiting_for_debugger", false),

                ["root_files"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("found_paths", new List<string>())
                    .With("build_tags", "release-keys")
                    .With("test_keys", false),

                ["system_properties"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("properties", new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["ro.secure"] = "1",
                        ["ro.debuggable"] = "0",
                        ["ro.build.type"] = "user",
                        ["ro.build.tags"] = "release-keys",
                        ["ro.boot.verifiedbootstate"] = "green",
                        ["ro.boot.flash.locked"] = "1",
                        ["ro.boot.vbmeta.device_state"] = "locked",
                        ["ro.boot.veritymode"] = "enforcing",
                    }),

                ["runtime_maps"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("suspicious_tokens", new List<string>())
                    .With("suspicious_line_count", 0),

                ["tracer"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("tracer_pid", 0)
                    .With("seccomp", 2)
                    .With("no_new_privs", 1),

                ["root_shell"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("su_path", string.Empty)
                    .With("su_found", false),

                ["selinux"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("mode", "enforcing")
                    .With("getenforce", "Enforcing")
                    .With("enforce_value", "1"),

                ["mounts"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("protected_rw_mounts", new List<string>()),

                ["frida_ports"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("open_ports", new List<int>()),

                ["instrumentation_threads"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("frida_threads", new List<string>())
                    .With("glib_threads", new List<string>())
                    .With("token_threads", new List<string>())
                    .With("thread_count", 42),

                ["exec_mappings"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("wx_mappings", 0)
                    .With("deleted_exec_mappings", 0)
                    .With("deleted_exec_jit", 1)
                    .With("anon_exec_labeled", 1)
                    .With("anon_exec_unlabeled", 0)
                    .With("samples", new List<string>()),

                ["code_integrity"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("checked", true)
                    .With("diff_bytes", 0)
                    .With("core_compared_bytes", 614400)
                    .With("core_diff_bytes", 0)
                    .With("ext_compared_bytes", 2097152)
                    .With("ext_diff_bytes", 0)
                    .With("ext_libs_diff", 0)
                    .With("app_compared_bytes", 4194304)
                    .With("app_diff_bytes", 0)
                    .With("app_libs_diff", 0)
                    .With("diffed_libs", string.Empty),

                ["emulator"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("suspected", false),

                ["developer_settings"] = ProbeResult.Ok()
                    .With("fixture", FixtureLabel)
                    .With("developer_options_enabled", false)
                    .With("adb_enabled", false),
            };
        }

        private static readonly RandomNumberGenerator Entropy = RandomNumberGenerator.Create();

        /// <summary>Produces a random reinstall-hint digest so each harness run enrols as a distinct device.</summary>
        public static string RandomHintDigest()
        {
            var bytes = new byte[16];
            Entropy.GetBytes(bytes);
            return Hex.Sha256Hex(bytes);
        }
    }
}
