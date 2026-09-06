using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Provider;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Maui.Android
{
    /// <summary>
    /// The Android integrity probe set: the .NET port of the Kotlin
    /// <c>IntegrityProbeManager</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every probe here reports a raw measurement. None of them decides anything:
    /// the server owns the scoring table, and a client-supplied verdict would be
    /// the first thing an attacker forged. A probe that cannot read what it needs
    /// reports <c>error</c> or <c>unsupported</c> and takes the server's penalty,
    /// because an unavailable measurement is not a clean one.
    /// </para>
    /// <para>
    /// The structural probes — <c>instrumentation_threads</c>,
    /// <c>exec_mappings</c> and <c>code_integrity</c> — matter more than the
    /// name-matching ones. DESIGN.md 27.11 records a confirmed evasion:
    /// renaming an injected Frida library and moving it off port 27042 defeats
    /// <c>runtime_maps</c> and <c>frida_ports</c> entirely. The structural probes
    /// survive that, because Gum's thread names are compiled into the framework
    /// and an inline hook changes bytes whatever the library is called.
    /// </para>
    /// <para>
    /// There are deliberately no debug test fixtures in this port. The Kotlin
    /// collector carries a set, gated on a debuggable APK, because that was how
    /// the server's scoring was proved without rooting the two test handsets;
    /// this SDK ships that capability in the console harness instead, where it
    /// cannot end up inside a customer's application at all.
    /// </para>
    /// </remarks>
    public sealed class AndroidIntegrityCollector : IIntegrityProbeCollector
    {
        private const int MaxText = 8192;

        private static readonly string[] SuspiciousRuntimeTokens =
        {
            "frida", "gadget", "objection", "xposed", "lsposed",
            "substrate", "cydia", "zygisk", "riru", "magisk",
            "kernelsu", "apatch",
        };

        private static readonly string[] RootPaths =
        {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
            "/sbin/magisk", "/data/adb/magisk", "/data/adb/modules",
            "/data/adb/ksu", "/data/adb/ap", "/metadata/adb/magisk",
        };

        // Compiled into Frida's Gum runtime, so a renamed injected library keeps
        // them. gum-js-loop is the Gum JavaScript event loop.
        private static readonly string[] FridaThreadNames = { "gum-js-loop", "gum-js", "pool-frida" };

        // GLib threads: Frida depends on GLib and Android apps almost never link
        // it themselves. Reported separately so the server can weight them as
        // corroborating rather than conclusive.
        private static readonly string[] GlibThreadNames = { "gmain", "gdbus", "pool-spawner" };

        private static readonly string[] SystemPropertyNames =
        {
            "ro.secure", "ro.debuggable", "ro.build.type", "ro.build.tags",
            "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state", "ro.boot.veritymode",
        };

        private static readonly string[] ProtectedMountPrefixes =
        {
            "/system", "/vendor", "/product", "/odm", "/system_ext",
        };

        private readonly Context _context;
        private string? _cachedApkSha256;

        /// <summary>Creates a collector for the current application context.</summary>
        public AndroidIntegrityCollector(Context context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        /// <inheritdoc />
        public string Platform => "android";

        /// <summary>
        /// Two, not one.
        /// </summary>
        /// <remarks>
        /// The reference implementation versions its Android collector per
        /// platform, and v2 is the set that adds <c>instrumentation_threads</c>,
        /// <c>exec_mappings</c> and <c>code_integrity</c> to the v1 baseline —
        /// which is exactly this set. Every stored report carries the value, so a
        /// report says which probe set produced it; DESIGN.md 29.2 exists because
        /// a whole run of database batteries had to be stamped as v1 after the
        /// fact so the results would not be misread later.
        /// </remarks>
        public int CollectorVersion => 2;

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

            var probes = new Dictionary<string, ProbeResult>(StringComparer.Ordinal);
            foreach (var name in requiredProbes.Distinct(StringComparer.Ordinal))
            {
                try
                {
                    probes[name] = RunProbe(name);
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    probes[name] = ProbeResult.Error(error.GetType().Name, error.Message ?? "probe failed");
                }
            }

            return Task.FromResult(new IntegrityCollection(Platform, CollectorVersion, challengeNonce, probes));
        }

        private ProbeResult RunProbe(string name)
        {
            return name switch
            {
                "app_identity" => ProbeAppIdentity(),
                "debug_state" => ProbeDebugState(),
                "root_files" => ProbeRootFiles(),
                "root_shell" => ProbeRootShell(),
                "system_properties" => ProbeSystemProperties(),
                "selinux" => ProbeSelinux(),
                "mounts" => ProbeMounts(),
                "runtime_maps" => ProbeRuntimeMaps(),
                "tracer" => ProbeTracer(),
                "frida_ports" => ProbeFridaPorts(),
                "emulator" => ProbeEmulator(),
                "developer_settings" => ProbeDeveloperSettings(),
                "instrumentation_threads" => ProbeInstrumentationThreads(),
                "exec_mappings" => ProbeExecMappings(),
                "code_integrity" => ProbeCodeIntegrity(),
                _ => ProbeResult.Unsupported("Unknown probe requested by the server: " + name),
            };
        }

        private ProbeResult ProbeAppIdentity()
        {
            var packageManager = _context.PackageManager
                                 ?? throw new InvalidOperationException("No PackageManager is available.");
            var packageName = _context.PackageName!;
            var certificates = new List<string>();

            PackageInfo? packageInfo;
            // OperatingSystem.IsAndroidVersionAtLeast is the form the
            // platform-compatibility analyzer recognises as a guard; a
            // Build.VERSION.SdkInt comparison is correct at run time but leaves
            // CA1416 unsatisfied at compile time.
            if (OperatingSystem.IsAndroidVersionAtLeast(28))
            {
                packageInfo = packageManager.GetPackageInfo(packageName, PackageInfoFlags.SigningCertificates);
                var signingInfo = packageInfo?.SigningInfo;
                var signatures = signingInfo is null
                    ? Array.Empty<Signature>()
                    : signingInfo.HasMultipleSigners
                        ? signingInfo.GetApkContentsSigners() ?? Array.Empty<Signature>()
                        : signingInfo.GetSigningCertificateHistory() ?? Array.Empty<Signature>();
                foreach (var signature in signatures)
                {
                    var bytes = signature?.ToByteArray();
                    if (bytes is not null)
                    {
                        certificates.Add(Hex.Sha256Hex(bytes));
                    }
                }
            }
            else
            {
#pragma warning disable CA1422 // GET_SIGNATURES is the only option before API 28.
                packageInfo = packageManager.GetPackageInfo(packageName, PackageInfoFlags.Signatures);
                foreach (var signature in packageInfo?.Signatures ?? Array.Empty<Signature>())
                {
                    var bytes = signature?.ToByteArray();
                    if (bytes is not null)
                    {
                        certificates.Add(Hex.Sha256Hex(bytes));
                    }
                }
#pragma warning restore CA1422
            }

            certificates.Sort(StringComparer.Ordinal);

            var applicationInfo = packageInfo?.ApplicationInfo ?? _context.ApplicationInfo!;
            var sourceDir = applicationInfo.SourceDir ?? string.Empty;
            _cachedApkSha256 ??= string.IsNullOrEmpty(sourceDir) ? string.Empty : Sha256File(sourceDir);

            var installer = ReadInstallerPackage(packageManager, packageName);
            var versionCode = OperatingSystem.IsAndroidVersionAtLeast(28)
                ? packageInfo?.LongVersionCode ?? 0L
                : GetLegacyVersionCode(packageInfo);

            return ProbeResult.Ok()
                .With("package_name", packageName)
                .With("version_name", packageInfo?.VersionName ?? string.Empty)
                .With("version_code", versionCode)
                .With("debuggable", (applicationInfo.Flags & ApplicationInfoFlags.Debuggable) != 0)
                .With("allow_backup", (applicationInfo.Flags & ApplicationInfoFlags.AllowBackup) != 0)
                .With("cert_sha256", certificates)
                .With("apk_sha256", _cachedApkSha256)
                .With("installer_package", installer)
                .With("source_dir", sourceDir);
        }

        private static ProbeResult ProbeDebugState()
        {
            return ProbeResult.Ok()
                .With("debugger_connected", global::Android.OS.Debug.IsDebuggerConnected)
                .With("waiting_for_debugger", global::Android.OS.Debug.WaitingForDebugger());
        }

        private static ProbeResult ProbeRootFiles()
        {
            var found = new List<string>();
            foreach (var path in RootPaths)
            {
                try
                {
                    if (File.Exists(path) || Directory.Exists(path))
                    {
                        found.Add(path);
                    }
                }
                catch (IOException)
                {
                    // A path the sandbox refuses to stat is not evidence either way.
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            var tags = Build.Tags ?? string.Empty;
            return ProbeResult.Ok()
                .With("found_paths", found)
                .With("build_tags", tags)
                .With("test_keys", tags.Contains("test-keys", StringComparison.OrdinalIgnoreCase));
        }

        private static ProbeResult ProbeRootShell()
        {
            var output = RunCommand("/system/bin/sh", "-c", "command -v su || which su || true").Trim();
            return ProbeResult.Ok()
                .With("su_path", Truncate(output, 512))
                .With("su_found", output.Length > 0);
        }

        private static ProbeResult ProbeSystemProperties()
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in SystemPropertyNames)
            {
                values[name] = Truncate(RunCommand("/system/bin/getprop", name).Trim(), 256);
            }

            return ProbeResult.Ok().With("properties", values);
        }

        private static ProbeResult ProbeSelinux()
        {
            // Two independent views, because some OEMs do not expose getenforce
            // to an ordinary application even on an enforcing device. An
            // unreadable state is telemetry, not evidence: the server scores only
            // an explicit permissive or disabled answer, which is the fix for the
            // false positive recorded against the OPPO in DESIGN.md.
            var mode = RunCommand("/system/bin/sh", "-c", "getenforce 2>/dev/null || true")
                .Trim()
                .Split('\n')
                .FirstOrDefault() ?? string.Empty;
            mode = Truncate(mode, 64);

            var enforceValue = string.Empty;
            try
            {
                const string EnforcePath = "/sys/fs/selinux/enforce";
                if (File.Exists(EnforcePath))
                {
                    enforceValue = Truncate(File.ReadAllText(EnforcePath).Trim(), 8);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }

            var normalized = mode.Equals("Enforcing", StringComparison.OrdinalIgnoreCase) ? "enforcing"
                : mode.Equals("Permissive", StringComparison.OrdinalIgnoreCase) ? "permissive"
                : mode.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ? "disabled"
                : enforceValue == "1" ? "enforcing"
                : enforceValue == "0" ? "permissive"
                : "unknown";

            return ProbeResult.Ok()
                .With("mode", normalized)
                .With("getenforce", mode)
                .With("enforce_value", enforceValue);
        }

        private static ProbeResult ProbeMounts()
        {
            var writable = new List<string>();
            foreach (var line in ReadLines("/proc/mounts"))
            {
                var parts = line.Split(' ');
                if (parts.Length < 4)
                {
                    continue;
                }

                var mountPoint = parts[1];
                var options = parts[3].Split(',');
                var isProtected = ProtectedMountPrefixes.Any(prefix =>
                    string.Equals(mountPoint, prefix, StringComparison.Ordinal)
                    || mountPoint.StartsWith(prefix + "/", StringComparison.Ordinal));

                if (isProtected && options.Contains("rw", StringComparer.Ordinal))
                {
                    writable.Add(mountPoint + ":" + parts[3]);
                }
            }

            return ProbeResult.Ok()
                .With("protected_rw_mounts", writable.Distinct(StringComparer.Ordinal).Take(32).ToList());
        }

        private static ProbeResult ProbeRuntimeMaps()
        {
            var found = new List<string>();
            var suspiciousLines = 0;

            foreach (var original in ReadLines("/proc/self/maps"))
            {
                var line = original.ToLowerInvariant();
                var matched = false;
                foreach (var token in SuspiciousRuntimeTokens)
                {
                    if (line.Contains(token, StringComparison.Ordinal))
                    {
                        if (!found.Contains(token, StringComparer.Ordinal))
                        {
                            found.Add(token);
                        }

                        matched = true;
                    }
                }

                if (matched)
                {
                    suspiciousLines++;
                }
            }

            return ProbeResult.Ok()
                .With("suspicious_tokens", found)
                .With("suspicious_line_count", suspiciousLines);
        }

        private static ProbeResult ProbeTracer()
        {
            var tracerPid = 0;
            var seccomp = -1;
            var noNewPrivs = -1;

            foreach (var line in ReadLines("/proc/self/status"))
            {
                if (line.StartsWith("TracerPid:", StringComparison.Ordinal))
                {
                    tracerPid = ParseTrailingInt(line, 0);
                }
                else if (line.StartsWith("Seccomp:", StringComparison.Ordinal))
                {
                    seccomp = ParseTrailingInt(line, -1);
                }
                else if (line.StartsWith("NoNewPrivs:", StringComparison.Ordinal))
                {
                    noNewPrivs = ParseTrailingInt(line, -1);
                }
            }

            return ProbeResult.Ok()
                .With("tracer_pid", tracerPid)
                .With("seccomp", seccomp)
                .With("no_new_privs", noNewPrivs);
        }

        private static ProbeResult ProbeFridaPorts()
        {
            var open = new List<int>();
            foreach (var port in new[] { 27042, 27043 })
            {
                try
                {
                    using var socket = new TcpClient();
                    var connect = socket.ConnectAsync("127.0.0.1", port);
                    if (connect.Wait(TimeSpan.FromMilliseconds(80)) && socket.Connected)
                    {
                        open.Add(port);
                    }
                }
                catch (SocketException)
                {
                    // Connection refused is the normal, healthy answer.
                }
                catch (System.AggregateException)
                {
                }
            }

            return ProbeResult.Ok().With("open_ports", open);
        }

        private static ProbeResult ProbeEmulator()
        {
            var reasons = new List<string>();
            bool Contains(string? value, string token) =>
                value is not null && value.Contains(token, StringComparison.OrdinalIgnoreCase);

            if ((Build.Fingerprint?.StartsWith("generic", StringComparison.Ordinal) ?? false)
                || Contains(Build.Fingerprint, "emulator"))
            {
                reasons.Add("fingerprint");
            }

            if (Contains(Build.Model, "google_sdk") || Contains(Build.Model, "emulator")
                || Contains(Build.Model, "android sdk built for"))
            {
                reasons.Add("model");
            }

            if (Contains(Build.Manufacturer, "genymotion"))
            {
                reasons.Add("manufacturer");
            }

            if (Contains(Build.Product, "sdk") || Contains(Build.Product, "emulator")
                || Contains(Build.Product, "simulator"))
            {
                reasons.Add("product");
            }

            if (Contains(Build.Hardware, "goldfish") || Contains(Build.Hardware, "ranchu"))
            {
                reasons.Add("hardware");
            }

            if (Contains(Build.Board, "goldfish"))
            {
                reasons.Add("board");
            }

            return ProbeResult.Ok()
                .With("suspected", reasons.Count > 0)
                .With("reasons", reasons)
                .With("model", Build.Model ?? string.Empty)
                .With("manufacturer", Build.Manufacturer ?? string.Empty)
                .With("product", Build.Product ?? string.Empty)
                .With("hardware", Build.Hardware ?? string.Empty);
        }

        private ProbeResult ProbeDeveloperSettings()
        {
            var resolver = _context.ContentResolver;
            var adb = false;
            var developer = false;

            try
            {
                adb = Settings.Global.GetInt(resolver, Settings.Global.AdbEnabled, 0) != 0;
            }
            catch (Exception)
            {
                // Unreadable settings are telemetry; the server treats absence as
                // "not enabled" rather than as a signal.
            }

            try
            {
                developer = Settings.Global.GetInt(
                    resolver,
                    Settings.Global.DevelopmentSettingsEnabled,
                    0) != 0;
            }
            catch (Exception)
            {
            }

            return ProbeResult.Ok()
                .With("adb_enabled", adb)
                .With("developer_options_enabled", developer);
        }

        private static ProbeResult ProbeInstrumentationThreads()
        {
            // Reads /proc/self/task/<tid>/comm, which a process may always read
            // for its own threads whatever SELinux says. This is what catches an
            // idle, renamed Frida Gadget that runtime_maps and frida_ports miss.
            var fridaHits = new List<string>();
            var glibHits = new List<string>();
            var tokenHits = new List<string>();
            var count = 0;

            string[] tasks;
            try
            {
                tasks = Directory.GetDirectories("/proc/self/task");
            }
            catch (IOException)
            {
                return ProbeResult.Error("IOException", "/proc/self/task could not be listed.");
            }
            catch (UnauthorizedAccessException)
            {
                return ProbeResult.Error("UnauthorizedAccessException", "/proc/self/task could not be listed.");
            }

            foreach (var task in tasks)
            {
                string name;
                try
                {
                    name = File.ReadAllText(Path.Combine(task, "comm")).Trim();
                }
                catch (Exception)
                {
                    continue;
                }

                if (name.Length == 0)
                {
                    continue;
                }

                count++;
                var lower = name.ToLowerInvariant();

                foreach (var candidate in FridaThreadNames)
                {
                    if ((string.Equals(lower, candidate, StringComparison.Ordinal)
                         || lower.StartsWith(candidate, StringComparison.Ordinal))
                        && !fridaHits.Contains(candidate, StringComparer.Ordinal))
                    {
                        fridaHits.Add(candidate);
                    }
                }

                foreach (var candidate in GlibThreadNames)
                {
                    if (string.Equals(lower, candidate, StringComparison.Ordinal)
                        && !glibHits.Contains(candidate, StringComparer.Ordinal))
                    {
                        glibHits.Add(candidate);
                    }
                }

                foreach (var candidate in SuspiciousRuntimeTokens)
                {
                    if (lower.Contains(candidate, StringComparison.Ordinal)
                        && !tokenHits.Contains(candidate, StringComparer.Ordinal))
                    {
                        tokenHits.Add(candidate);
                    }
                }
            }

            return ProbeResult.Ok()
                .With("frida_threads", fridaHits)
                .With("glib_threads", glibHits)
                .With("token_threads", tokenHits)
                .With("thread_count", count);
        }

        private static ProbeResult ProbeExecMappings()
        {
            var wx = 0;
            var deletedExec = 0;
            var deletedExecJit = 0;
            var anonExecLabeled = 0;
            var anonExecUnlabeled = 0;
            var samples = new List<string>();

            foreach (var raw in ReadLines("/proc/self/maps"))
            {
                var line = raw.Trim();
                var parts = line.Split(new[] { ' ', '\t' }, 6, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5)
                {
                    continue;
                }

                var permissions = parts[1];
                if (permissions.Length < 4 || permissions[2] != 'x')
                {
                    continue;
                }

                var path = parts.Length >= 6 ? parts[5] : string.Empty;
                if (permissions[1] == 'w')
                {
                    wx++;
                    if (samples.Count < 8)
                    {
                        samples.Add(Truncate(line, 160));
                    }
                }

                if (path.Contains("(deleted)", StringComparison.Ordinal))
                {
                    // The ART JIT code cache is executable and "(deleted)" on
                    // every clean device. Excluding it here is what stops the
                    // whole fleet from being a false positive.
                    var lower = path.ToLowerInvariant();
                    var isJit = lower.Contains("jit-cache", StringComparison.Ordinal)
                                || lower.Contains("dalvik-jit-code-cache", StringComparison.Ordinal)
                                || lower.Contains("dalvik-", StringComparison.Ordinal)
                                || lower.Contains("/art", StringComparison.Ordinal)
                                || lower.Contains("jit-zygote", StringComparison.Ordinal);
                    if (isJit)
                    {
                        deletedExecJit++;
                    }
                    else
                    {
                        deletedExec++;
                        if (samples.Count < 8)
                        {
                            samples.Add(Truncate(line, 160));
                        }
                    }
                }

                if (path.Length == 0)
                {
                    anonExecUnlabeled++;
                }
                else if (path.StartsWith("[anon:", StringComparison.Ordinal))
                {
                    anonExecLabeled++;
                }
            }

            return ProbeResult.Ok()
                .With("wx_mappings", wx)
                .With("deleted_exec_mappings", deletedExec)
                .With("deleted_exec_jit", deletedExecJit)
                .With("anon_exec_labeled", anonExecLabeled)
                .With("anon_exec_unlabeled", anonExecUnlabeled)
                .With("samples", samples);
        }

        private ProbeResult ProbeCodeIntegrity()
        {
            // Managed, with no native component. /proc/self/maps is an ordinary
            // file read and Marshal.Copy reads this process's own mapped pages by
            // pointer, so the SELinux block on /proc/self/mem that forced the
            // reference implementation into an NDK component does not apply here.
            var measurement = ManagedCodeIntegrity.Measure();
            if (!measurement.Checked)
            {
                return ProbeResult.Ok()
                    .With("checked", false)
                    .With("reason", measurement.Reason);
            }

            return ProbeResult.Ok()
                .With("checked", true)
                // diff_bytes is the CORE bucket. The server reads this field as
                // the core figure and adds ext separately; reporting a combined
                // total here would double-count the extended bucket.
                .With("diff_bytes", measurement.CoreDiffBytes)
                .With("core_compared_bytes", measurement.CoreComparedBytes)
                .With("core_diff_bytes", measurement.CoreDiffBytes)
                .With("ext_compared_bytes", measurement.ExtComparedBytes)
                .With("ext_diff_bytes", measurement.ExtDiffBytes)
                .With("ext_libs_diff", measurement.ExtLibrariesDiffering)
                .With("app_compared_bytes", measurement.AppComparedBytes)
                .With("app_diff_bytes", measurement.AppDiffBytes)
                .With("app_libs_diff", measurement.AppLibrariesDiffering)
                .With("diffed_libs", measurement.DiffedLibraries)
                // Emitted so an operator can tell an inert bucket from a clean
                // one at a glance. A bucket with compared_bytes = 0 measured
                // nothing; treating that as "no difference found" is the defect
                // that shipped once in the reference implementation.
                .With("core_bucket_live", measurement.CoreComparedBytes > 0)
                .With("ext_bucket_live", measurement.ExtComparedBytes > 0)
                .With("app_bucket_live", measurement.AppComparedBytes > 0)
                // Android 10+ maps system libraries execute-only. These say how
                // many such regions had to be temporarily made readable, and how
                // many could not be -- the second number is what separates an
                // incomplete measurement from a clean one.
                .With("xom_regions_unlocked", measurement.ExecuteOnlyRegionsUnlocked)
                .With("xom_regions_unreadable", measurement.ExecuteOnlyRegionsUnreadable);
        }

        private static string? ReadInstallerPackage(PackageManager packageManager, string packageName)
        {
            try
            {
                if (OperatingSystem.IsAndroidVersionAtLeast(30))
                {
                    return packageManager.GetInstallSourceInfo(packageName)?.InstallingPackageName;
                }

#pragma warning disable CA1422 // The replacement API arrived in API 30.
                return packageManager.GetInstallerPackageName(packageName);
#pragma warning restore CA1422
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static long GetLegacyVersionCode(PackageInfo? packageInfo)
        {
#pragma warning disable CA1422 // LongVersionCode arrived in API 28.
            return packageInfo?.VersionCode ?? 0;
#pragma warning restore CA1422
        }

        private static IEnumerable<string> ReadLines(string path)
        {
            string[] lines;
            try
            {
                lines = File.ReadAllLines(path);
            }
            catch (IOException)
            {
                return Array.Empty<string>();
            }
            catch (UnauthorizedAccessException)
            {
                return Array.Empty<string>();
            }

            return lines;
        }

        private static int ParseTrailingInt(string line, int fallback)
        {
            var separator = line.IndexOf(':');
            if (separator < 0)
            {
                return fallback;
            }

            return int.TryParse(
                line.Substring(separator + 1).Trim(),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var parsed)
                ? parsed
                : fallback;
        }

        private static string RunCommand(string command, params string[] arguments)
        {
            try
            {
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = command,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                    },
                };

                foreach (var argument in arguments)
                {
                    process.StartInfo.ArgumentList.Add(argument);
                }

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit(2000);
                return Truncate(output, MaxText);
            }
            catch (Exception)
            {
                // A command an app is not allowed to run yields no measurement,
                // which the caller reports as an empty value rather than as a
                // security conclusion.
                return string.Empty;
            }
        }

        private static string Sha256File(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                return Hex.Encode(sha256.ComputeHash(stream));
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        private static string Truncate(string value, int maximum)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value.Length <= maximum ? value : value.Substring(0, maximum);
        }
    }
}
