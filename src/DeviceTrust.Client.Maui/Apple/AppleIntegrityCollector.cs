using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Internal;
using Foundation;
using ObjCRuntime;

namespace DeviceTrust.Client.Maui.Apple
{
    /// <summary>
    /// The iOS integrity probe set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// iOS gives an application far less visibility into its own device than
    /// Android does: there is no <c>/proc</c>, no way to enumerate mounts, and no
    /// system properties. What remains is still meaningful — which images the
    /// dynamic linker loaded, whether the process is traced, whether the sandbox
    /// actually holds, whether jailbreak artefacts are visible, and what the code
    /// signature says — and those are the probes here.
    /// </para>
    /// <para>
    /// The strongest single signal is <c>dyld_images</c>: on a jailbroken device
    /// a hooking framework has to be loaded into the process to do anything, and
    /// it is visible in the image list whatever it is called.
    /// </para>
    /// </remarks>
    public sealed class AppleIntegrityCollector : IIntegrityProbeCollector
    {
        private static readonly string[] SuspiciousImageTokens =
        {
            "frida", "gadget", "objection", "substrate", "mobilesubstrate",
            "substitute", "libhooker", "ellekit", "cydia", "cycript",
        };

        private static readonly string[] JailbreakPaths =
        {
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/substitute-inserter.dylib",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/bin/bash",
            "/bin/sh",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/var/jb",
        };

        /// <inheritdoc />
        public string Platform => "ios";

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

        private static ProbeResult RunProbe(string name)
        {
            return name switch
            {
                "app_identity" => ProbeAppIdentity(),
                "code_signing" => ProbeCodeSigning(),
                "debugger" => ProbeDebugger(),
                "jailbreak_files" => ProbeJailbreakFiles(),
                "sandbox" => ProbeSandbox(),
                "dyld_images" => ProbeDyldImages(),
                "environment" => ProbeEnvironment(),
                "simulator" => ProbeSimulator(),
                _ => ProbeResult.Unsupported("Unknown probe requested by the server: " + name),
            };
        }

        private static ProbeResult ProbeAppIdentity()
        {
            var bundle = NSBundle.MainBundle;
            var executablePath = bundle?.ExecutablePath;
            var result = ProbeResult.Ok()
                .With("bundle_id", bundle?.BundleIdentifier ?? string.Empty)
                .With("version", bundle?.InfoDictionary?["CFBundleShortVersionString"]?.ToString() ?? string.Empty)
                .With("build", bundle?.InfoDictionary?["CFBundleVersion"]?.ToString() ?? string.Empty);

            if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
            {
                return result.With("executable_readable", false);
            }

            using var stream = File.OpenRead(executablePath!);
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            return result
                .With("executable_readable", true)
                .With("executable_sha256", Hex.Encode(sha256.ComputeHash(stream)));
        }

        private static ProbeResult ProbeCodeSigning()
        {
            // iOS has no public SecCodeCopySigningInformation. What an app can
            // read about its own signature is its entitlements, and the two that
            // matter are the team identifier and get-task-allow: the latter is
            // set only in development builds and is what lets a debugger attach.
            var applicationIdentifier = ReadStringEntitlement("application-identifier")
                                        ?? ReadStringEntitlement("com.apple.application-identifier");
            var teamIdentifier = ReadStringEntitlement("com.apple.developer.team-identifier");
            var getTaskAllow = ReadBooleanEntitlement("get-task-allow");

            return ProbeResult.Ok()
                .With("signing_identifier", applicationIdentifier ?? string.Empty)
                .With("team_identifier", teamIdentifier ?? string.Empty)
                .With("get_task_allow", getTaskAllow ?? false)
                .With("entitlements_readable", applicationIdentifier is not null || teamIdentifier is not null);
        }

        private static ProbeResult ProbeDebugger()
        {
            return ProbeResult.Ok()
                .With("traced", IsProcessTraced())
                .With("managed_debugger_attached", System.Diagnostics.Debugger.IsAttached);
        }

        private static ProbeResult ProbeJailbreakFiles()
        {
            var found = new List<string>();
            foreach (var path in JailbreakPaths)
            {
                try
                {
                    if (File.Exists(path) || Directory.Exists(path))
                    {
                        found.Add(path);
                    }
                }
                catch (Exception)
                {
                    // A sandboxed app is denied most of these, which is the
                    // healthy answer and not a measurement failure.
                }
            }

            return ProbeResult.Ok().With("found_paths", found);
        }

        private static ProbeResult ProbeSandbox()
        {
            // Writing outside the container is impossible under an intact
            // sandbox. Success means the sandbox is not holding, which the server
            // treats as a hard block.
            var probePath = "/private/" + Guid.NewGuid().ToString("N") + ".devicetrust";
            var succeeded = false;
            try
            {
                File.WriteAllText(probePath, "sandbox probe");
                succeeded = true;
                File.Delete(probePath);
            }
            catch (Exception)
            {
                succeeded = false;
            }

            return ProbeResult.Ok().With("write_outside_sandbox_succeeded", succeeded);
        }

        private static ProbeResult ProbeDyldImages()
        {
            var tokens = new List<string>();
            var suspiciousCount = 0;
            var imageCount = (int)DyldImageCount();

            for (var index = 0; index < imageCount; index++)
            {
                var namePointer = DyldGetImageName((uint)index);
                if (namePointer == IntPtr.Zero)
                {
                    continue;
                }

                var name = (Marshal.PtrToStringAnsi(namePointer) ?? string.Empty).ToLowerInvariant();
                var matched = false;
                foreach (var token in SuspiciousImageTokens)
                {
                    if (name.Contains(token, StringComparison.Ordinal))
                    {
                        if (!tokens.Contains(token, StringComparer.Ordinal))
                        {
                            tokens.Add(token);
                        }

                        matched = true;
                    }
                }

                if (matched)
                {
                    suspiciousCount++;
                }
            }

            return ProbeResult.Ok()
                .With("suspicious_tokens", tokens)
                .With("suspicious_image_count", suspiciousCount)
                .With("image_count", imageCount);
        }

        private static ProbeResult ProbeEnvironment()
        {
            return ProbeResult.Ok()
                .With("dyld_insert_libraries", Environment.GetEnvironmentVariable("DYLD_INSERT_LIBRARIES") ?? string.Empty)
                .With("dyld_library_path", Environment.GetEnvironmentVariable("DYLD_LIBRARY_PATH") ?? string.Empty);
        }

        private static ProbeResult ProbeSimulator()
        {
            var isSimulator = Runtime.Arch == Arch.SIMULATOR
                              || !string.IsNullOrEmpty(
                                  Environment.GetEnvironmentVariable("SIMULATOR_DEVICE_NAME"));
            return ProbeResult.Ok().With("is_simulator", isSimulator);
        }

        private static bool IsProcessTraced()
        {
            // sysctl(KERN_PROC, KERN_PROC_PID, pid) fills a kinfo_proc. The
            // P_TRACED flag lives in kp_proc.p_flag, at a fixed 32-byte offset on
            // 64-bit Darwin: a 16-byte list union, then two 8-byte pointers.
            const int CtlKern = 1;
            const int KernProc = 14;
            const int KernProcPid = 1;
            const int PFlagOffset = 32;
            const int PTraced = 0x00000800;

            var name = new int[] { CtlKern, KernProc, KernProcPid, Environment.ProcessId };
            var size = (IntPtr)648;
            var buffer = Marshal.AllocHGlobal(648);
            try
            {
                if (Sysctl(name, (uint)name.Length, buffer, ref size, IntPtr.Zero, IntPtr.Zero) != 0)
                {
                    return false;
                }

                var flags = Marshal.ReadInt32(buffer, PFlagOffset);
                return (flags & PTraced) != 0;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string? ReadStringEntitlement(string name)
        {
            using var value = CopyEntitlement(name);
            return value is NSString text ? text.ToString() : null;
        }

        private static bool? ReadBooleanEntitlement(string name)
        {
            using var value = CopyEntitlement(name);
            return value is NSNumber number ? number.BoolValue : null;
        }

        private static NSObject? CopyEntitlement(string name)
        {
            var task = SecTaskCreateFromSelf(IntPtr.Zero);
            if (task == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                using var key = new NSString(name);
                var value = SecTaskCopyValueForEntitlement(task, key.Handle, IntPtr.Zero);
                return value == IntPtr.Zero ? null : Runtime.GetNSObject(value);
            }
            finally
            {
                CFRelease(task);
            }
        }

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "sysctl")]
        private static extern int Sysctl(int[] name, uint nameLength, IntPtr oldp, ref IntPtr oldlenp, IntPtr newp, IntPtr newlen);

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_image_count")]
        private static extern uint DyldImageCount();

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_get_image_name")]
        private static extern IntPtr DyldGetImageName(uint index);

        [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecTaskCreateFromSelf")]
        private static extern IntPtr SecTaskCreateFromSelf(IntPtr allocator);

        [DllImport("/System/Library/Frameworks/Security.framework/Security", EntryPoint = "SecTaskCopyValueForEntitlement")]
        private static extern IntPtr SecTaskCopyValueForEntitlement(IntPtr task, IntPtr entitlement, IntPtr error);

        [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
        private static extern void CFRelease(IntPtr handle);
    }
}
