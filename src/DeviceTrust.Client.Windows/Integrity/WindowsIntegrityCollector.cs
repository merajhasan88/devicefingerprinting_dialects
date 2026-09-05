using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using Microsoft.Win32;

namespace DeviceTrust.Client.Windows.Integrity
{
    /// <summary>
    /// A Windows-native integrity probe set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is a different design from the Android probe set, not a translation
    /// of it. Root binaries, SELinux, <c>/proc/self/maps</c> and Verified Boot
    /// have no Windows meaning; what a Windows process can actually observe about
    /// itself is Authenticode trust on its own image and on everything loaded
    /// into it, debugger presence including a kernel debugger, Secure Boot and
    /// test-signing state, and whether it is running elevated. Those are the
    /// probes here.
    /// </para>
    /// <para>
    /// <b>The server does not score these yet.</b> The device-trust server accepts
    /// <c>android</c> and <c>ios</c> platforms and rejects anything else with
    /// <c>unsupported_platform</c>, so a report from this collector cannot be
    /// submitted until a Windows scoring table exists server-side. Until then,
    /// this collector is useful for local diagnostics and as the client half of
    /// that work, and <see cref="CollectAsync"/> is deliberately usable on its
    /// own. Reporting a Windows machine as <c>android</c> to get past the gate
    /// would be exactly the dishonesty the whole integrity mechanism exists to
    /// prevent.
    /// </para>
    /// <para>
    /// Every measurement here is a local self-report from inside the process. An
    /// attacker holding administrator or kernel privilege can falsify all of it;
    /// that boundary is stated in DESIGN.md and is not different on Windows.
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsIntegrityCollector : IIntegrityProbeCollector
    {
        private static readonly string[] KnownInjectionModules =
        {
            "frida", "gum", "detours", "easyhook", "mhook", "minhook",
            "cheatengine", "speedhack", "dbghelp_hook", "winject", "hookdll",
        };

        /// <summary>
        /// The platform name this collector reports.
        /// </summary>
        /// <remarks>
        /// The current server rejects it with <c>unsupported_platform</c>. That
        /// is the honest failure and it is preferred to the alternative, which
        /// would be claiming a platform whose measurements this machine cannot
        /// produce.
        /// </remarks>
        public string Platform => "windows";

        /// <inheritdoc />
        public int CollectorVersion => 1;

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
                probes[name] = RunProbe(name);
            }

            return Task.FromResult(new IntegrityCollection(Platform, CollectorVersion, challengeNonce, probes));
        }

        /// <summary>
        /// Runs the full Windows probe set regardless of what a server asked for,
        /// for local diagnostics.
        /// </summary>
        public IReadOnlyDictionary<string, ProbeResult> CollectAll()
        {
            return new Dictionary<string, ProbeResult>(StringComparer.Ordinal)
            {
                ["app_identity"] = RunProbe("app_identity"),
                ["debugger"] = RunProbe("debugger"),
                ["loaded_modules"] = RunProbe("loaded_modules"),
                ["os_integrity"] = RunProbe("os_integrity"),
                ["process_state"] = RunProbe("process_state"),
            };
        }

        private ProbeResult RunProbe(string name)
        {
            try
            {
                return name switch
                {
                    "app_identity" => ProbeAppIdentity(),
                    "debugger" => ProbeDebugger(),
                    "loaded_modules" => ProbeLoadedModules(),
                    "os_integrity" => ProbeOsIntegrity(),
                    "process_state" => ProbeProcessState(),
                    _ => ProbeResult.Unsupported("The Windows collector has no probe named '" + name + "'."),
                };
            }
            catch (Exception error) when (error is not OutOfMemoryException and not StackOverflowException)
            {
                // A probe that throws is reported as failed, not omitted and not
                // replaced with a clean-looking value. The server penalises a
                // required probe that did not complete, which is the correct
                // outcome: an unreadable measurement is not a good measurement.
                return ProbeResult.Error(error.GetType().Name, error.Message);
            }
        }

        private static ProbeResult ProbeAppIdentity()
        {
            using var process = Process.GetCurrentProcess();
            var modulePath = process.MainModule?.FileName;
            var result = ProbeResult.Ok()
                .With("process_name", process.ProcessName)
                .With("image_path", modulePath ?? string.Empty);

            if (string.IsNullOrEmpty(modulePath) || !File.Exists(modulePath))
            {
                return result.With("image_readable", false);
            }

            var signature = Authenticode.Verify(modulePath!);
            return result
                .With("image_readable", true)
                .With("image_sha256", Hex.Sha256Hex(File.ReadAllBytes(modulePath!)))
                .With("signature_state", signature.State)
                .With("signer_subject", signature.Subject ?? string.Empty)
                .With("signer_thumbprint", signature.Thumbprint ?? string.Empty)
                .With("file_version", FileVersionInfo.GetVersionInfo(modulePath!).FileVersion ?? string.Empty);
        }

        private static ProbeResult ProbeDebugger()
        {
            var remotePresent = false;
            NativeMethods.CheckRemoteDebuggerPresent(NativeMethods.GetCurrentProcess(), ref remotePresent);

            var kernelDebugger = ReadRegistryString(
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control",
                "SystemStartOptions");

            return ProbeResult.Ok()
                .With("managed_debugger_attached", Debugger.IsAttached)
                .With("is_debugger_present", NativeMethods.IsDebuggerPresent())
                .With("remote_debugger_present", remotePresent)
                .With("boot_options", kernelDebugger ?? string.Empty)
                .With(
                    "kernel_debug_boot",
                    kernelDebugger is not null
                    && kernelDebugger.IndexOf("DEBUG", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static ProbeResult ProbeLoadedModules()
        {
            using var process = Process.GetCurrentProcess();
            var unsigned = new List<string>();
            var untrusted = new List<string>();
            var suspicious = new List<string>();
            var writableLocation = new List<string>();
            var inspected = 0;

            foreach (ProcessModule module in process.Modules)
            {
                var path = module.FileName;
                if (string.IsNullOrEmpty(path))
                {
                    continue;
                }

                inspected++;
                var fileName = Path.GetFileName(path).ToLowerInvariant();
                if (KnownInjectionModules.Any(token => fileName.Contains(token, StringComparison.Ordinal)))
                {
                    suspicious.Add(fileName);
                }

                var signature = Authenticode.Verify(path);
                switch (signature.State)
                {
                    case "unsigned":
                        unsigned.Add(fileName);
                        break;
                    case "valid":
                        break;
                    default:
                        untrusted.Add(fileName + ":" + signature.State);
                        break;
                }

                if (IsUserWritableLocation(path))
                {
                    writableLocation.Add(fileName);
                }
            }

            return ProbeResult.Ok()
                .With("modules_inspected", inspected)
                .With("unsigned_modules", Cap(unsigned))
                .With("untrusted_modules", Cap(untrusted))
                .With("suspicious_modules", Cap(suspicious))
                .With("user_writable_modules", Cap(writableLocation));
        }

        private static ProbeResult ProbeOsIntegrity()
        {
            var secureBoot = ReadRegistryInt(
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled");
            var bootOptions = ReadRegistryString(
                @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control",
                "SystemStartOptions") ?? string.Empty;

            return ProbeResult.Ok()
                .With("os_version", Environment.OSVersion.VersionString)
                .With("os_build", Environment.OSVersion.Version.Build)
                .With("is_64bit_os", Environment.Is64BitOperatingSystem)
                .With(
                    "secure_boot",
                    secureBoot is null ? "unknown" : (secureBoot.Value == 1 ? "enabled" : "disabled"))
                .With(
                    "test_signing",
                    bootOptions.IndexOf("TESTSIGNING", StringComparison.OrdinalIgnoreCase) >= 0)
                .With(
                    "no_integrity_checks",
                    bootOptions.IndexOf("DISABLE_INTEGRITY_CHECKS", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static ProbeResult ProbeProcessState()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            return ProbeResult.Ok()
                .With("elevated", principal.IsInRole(WindowsBuiltInRole.Administrator))
                .With("session_id", Process.GetCurrentProcess().SessionId)
                .With("interactive", Environment.UserInteractive)
                .With("machine_name_hash", Hex.Sha256Hex(Environment.MachineName));
        }

        private static bool IsUserWritableLocation(string path)
        {
            var directory = Path.GetDirectoryName(path);
            if (string.IsNullOrEmpty(directory))
            {
                return false;
            }

            var normalized = directory!.ToLowerInvariant();
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
            var temp = Path.GetTempPath().ToLowerInvariant().TrimEnd('\\');

            return (profile.Length > 0 && normalized.StartsWith(profile, StringComparison.Ordinal))
                   || (temp.Length > 0 && normalized.StartsWith(temp, StringComparison.Ordinal));
        }

        private static List<string> Cap(List<string> values)
        {
            return values.Distinct(StringComparer.Ordinal).Take(32).ToList();
        }

        private static string? ReadRegistryString(string keyPath, string valueName)
        {
            return Registry.GetValue(keyPath, valueName, null) as string;
        }

        private static int? ReadRegistryInt(string keyPath, string valueName)
        {
            var value = Registry.GetValue(keyPath, valueName, null);
            return value is null
                ? null
                : int.TryParse(
                    Convert.ToString(value, CultureInfo.InvariantCulture),
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var parsed)
                    ? parsed
                    : null;
        }
    }
}
