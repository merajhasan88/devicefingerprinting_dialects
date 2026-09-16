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

        /// <summary>Per-image ceiling for the code comparison, matching the Android probe.</summary>
        private const int MaxBytesPerImage = 4 * 1024 * 1024;

        /// <inheritdoc />
        public string Platform => "ios";

        /// <summary>
        /// Two, not one.
        /// </summary>
        /// <remarks>
        /// v1 was the eight-probe baseline set. v2 adds <c>code_integrity</c>,
        /// the dyld analogue of the Android probe, which is what battery item 16
        /// needs. The reference Swift collector versions the same way and for the
        /// same reason.
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
                probes[name] = SafeProbe(name);
            }

            // code_integrity is reported whether or not the server asked for it.
            // The server tolerates probes beyond the required set but rejects a
            // report that omits a requested one, so a new probe cannot be made
            // mandatory without breaking every client that predates it. A server
            // that already lists it will simply have run it in the loop above;
            // volunteering it lets an older server score it too, and lets the two
            // iOS clients adopt it independently. The reference collector does
            // exactly this.
            if (!probes.ContainsKey("code_integrity"))
            {
                probes["code_integrity"] = SafeProbe("code_integrity");
            }

            return Task.FromResult(new IntegrityCollection(Platform, CollectorVersion, challengeNonce, probes));
        }

        private static ProbeResult SafeProbe(string name)
        {
            try
            {
                return RunProbe(name);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                return ProbeResult.Error(error.GetType().Name, error.Message ?? "probe failed");
            }
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
                "code_integrity" => ProbeCodeIntegrity(),
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
            // Read this app's own code-signing identity by parsing the Mach-O
            // signature embedded in its executable, NOT SecTaskCopyValueForEntitlement.
            //
            // Two reasons. First, SecTaskCreateFromSelf is public API on macOS
            // only; on iOS the symbol is private, and though a DllImport builds
            // regardless it may resolve to nothing at runtime and return a clean-
            // looking empty result -- the exact trap this probe exists to avoid.
            // Second, and decisive: signing_identifier is a hard contract with
            // _score_ios_integrity, and the reference client puts the CodeDirectory
            // identifier there -- "com.example.app" -- while the application-identifier
            // entitlement carries "TEAMID.com.example.app". Reading the entitlement
            // would raise ios_signing_identifier_bundle_mismatch on every clean
            // device. The CodeDirectory identifier is also the stronger measurement:
            // it is what the signer embedded in the binary rather than what the
            // kernel was told at launch, and an unsigned build has no signature at
            // all, which is reported as signed=false instead of read as clean.
            var result = ProbeResult.Ok()
                .With("signing_identifier", string.Empty)
                .With("team_identifier", string.Empty)
                .With("get_task_allow", false)
                .With("signed", false);

            var executablePath = NSBundle.MainBundle?.ExecutablePath;
            if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
            {
                return result.With("status", "error").With("error", "The main executable could not be read.");
            }

            var bytes = File.ReadAllBytes(executablePath!);
            var image = MachOImage.TryParse(bytes);
            if (image is null)
            {
                return result.With("status", "error")
                    .With("error", "The main executable is not a recognised 64-bit Mach-O image.");
            }

            var signature = image.ReadCodeSignature();
            if (signature is null)
            {
                // No LC_CODE_SIGNATURE at all: the legitimate shape of an
                // unsigned jailbroken-device build. Reported as unsigned, never
                // mistaken for a clean signed app.
                return result.With("signature_absent", true);
            }

            if (signature.ParseError is not null)
            {
                return result.With("signed", true).With("signature_parse_error", signature.ParseError);
            }

            result = result
                .With("signed", true)
                .With("signing_identifier", signature.Identifier ?? string.Empty);

            if (signature.CodeDirectoryFlags is uint flags)
            {
                result = result.With("code_directory_flags", (long)flags);
            }

            if (signature.EntitlementsPlist is not null)
            {
                var entitlements = EntitlementsPlist.TryParse(signature.EntitlementsPlist);
                if (entitlements is not null)
                {
                    result = result
                        .With("team_identifier", AsString(entitlements, "com.apple.developer.team-identifier"))
                        .With("get_task_allow", entitlements.TryGetValue("get-task-allow", out var gta) && gta is true)
                        .With("entitlement_count", entitlements.Count);
                }
            }

            return result;
        }

        private static string AsString(IReadOnlyDictionary<string, object?> map, string key)
        {
            return map.TryGetValue(key, out var value) && value is string text ? text : string.Empty;
        }

        /// <summary>
        /// Compares each loaded image's <c>__TEXT,__text</c> in memory against
        /// the same bytes on disk.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The iOS analogue of the Android <c>code_integrity</c> probe, and the
        /// field names are a hard contract with the server's iOS scorer,
        /// mirroring the Android one.
        /// </para>
        /// <para>
        /// <b>Only the app bucket can be measured on iOS, and that is a platform
        /// fact rather than an omission.</b> Android compares libc and libart
        /// against real files under <c>/apex</c>. iOS system libraries do not
        /// exist as individual files at all: dyld merges them into the shared
        /// cache, so there is nothing to open for UIKit or libobjc. Those images
        /// are counted as <i>unreadable</i>, never as clean.
        /// </para>
        /// <para>
        /// That distinction is the whole point. An implementation that skipped
        /// them silently would report <c>ext_compared_bytes: 0,
        /// ext_diff_bytes: 0</c>, which scores exactly like a pristine device
        /// while having measured nothing — the same defect as an Android bucket
        /// reading as clean because it was inert. <c>checked</c> becomes true
        /// only if at least one bundle image really was compared.
        /// </para>
        /// </remarks>
        private static ProbeResult ProbeCodeIntegrity()
        {
            var bundlePath = NSBundle.MainBundle?.BundlePath ?? string.Empty;
            long appCompared = 0;
            long appDiff = 0;
            var appLibsDiff = 0;
            var imagesCompared = 0;
            var systemUnreadable = 0;
            var diffedLibs = new List<string>();

            var imageCount = (int)DyldImageCount();
            for (var index = 0; index < imageCount; index++)
            {
                var namePointer = DyldGetImageName((uint)index);
                if (namePointer == IntPtr.Zero)
                {
                    continue;
                }

                var path = Marshal.PtrToStringAnsi(namePointer) ?? string.Empty;

                // Anything outside our own bundle lives in the shared cache.
                // Counted, not compared, and never treated as clean.
                if (path.Length == 0 || bundlePath.Length == 0
                    || !path.StartsWith(bundlePath, StringComparison.Ordinal))
                {
                    systemUnreadable++;
                    continue;
                }

                byte[] fileBytes;
                try
                {
                    fileBytes = File.ReadAllBytes(path);
                }
                catch (Exception)
                {
                    // A bundle image we cannot read is also not clean.
                    systemUnreadable++;
                    continue;
                }

                var image = MachOImage.TryParse(fileBytes);
                var text = image?.FindSection("__TEXT", "__text");
                if (image is null || text is null || text.Value.Size <= 0)
                {
                    systemUnreadable++;
                    continue;
                }

                // Cap per image, as the Android probe does, so a large binary
                // cannot make a scan take unbounded time.
                var length = (int)Math.Min(text.Value.Size, MaxBytesPerImage);
                var diskOffset = image.SliceOffset + text.Value.FileOffset;
                if (diskOffset < 0 || diskOffset + length > fileBytes.LongLength)
                {
                    systemUnreadable++;
                    continue;
                }

                // The section's linked address plus dyld's slide is where the
                // image actually sits in this process.
                var slide = (long)DyldGetImageVmaddrSlide((uint)index);
                var live = (IntPtr)unchecked((long)text.Value.VirtualAddress + slide);
                if (live == IntPtr.Zero)
                {
                    systemUnreadable++;
                    continue;
                }

                var fromMemory = new byte[length];
                try
                {
                    Marshal.Copy(live, fromMemory, 0, length);
                }
                catch (Exception)
                {
                    systemUnreadable++;
                    continue;
                }

                var differing = 0;
                for (var offset = 0; offset < length; offset++)
                {
                    if (fromMemory[offset] != fileBytes[diskOffset + offset])
                    {
                        differing++;
                    }
                }

                imagesCompared++;
                appCompared += length;
                if (differing > 0)
                {
                    appDiff += differing;
                    appLibsDiff++;
                    diffedLibs.Add(Path.GetFileName(path));
                }
            }

            return ProbeResult.Ok()
                // checked means "the app bucket was genuinely compared". If no
                // bundle image could be read, nothing was measured, and saying
                // otherwise is the exact lie this probe exists to prevent.
                .With("checked", imagesCompared > 0)
                // Core and ext are the system buckets. On iOS they are
                // structurally unmeasurable, so they are reported as zero
                // compared WITH a reason, letting the server tell "nothing to
                // compare" apart from "compared and clean".
                .With("core_compared_bytes", 0)
                .With("core_diff_bytes", 0)
                .With("diff_bytes", 0)
                .With("ext_compared_bytes", 0)
                .With("ext_diff_bytes", 0)
                .With("ext_libs_diff", 0)
                .With("app_compared_bytes", appCompared)
                .With("app_diff_bytes", appDiff)
                .With("app_libs_diff", appLibsDiff)
                .With("app_images_compared", imagesCompared)
                .With("system_images_unreadable", systemUnreadable)
                .With("system_bucket_reason", "dyld_shared_cache_has_no_backing_files")
                .With("diffed_libs", string.Join(",", diffedLibs));
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

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "sysctl")]
        private static extern int Sysctl(int[] name, uint nameLength, IntPtr oldp, ref IntPtr oldlenp, IntPtr newp, IntPtr newlen);

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_image_count")]
        private static extern uint DyldImageCount();

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_get_image_name")]
        private static extern IntPtr DyldGetImageName(uint index);

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_get_image_header")]
        private static extern IntPtr DyldGetImageHeader(uint index);

        [DllImport("/usr/lib/libSystem.dylib", EntryPoint = "_dyld_get_image_vmaddr_slide")]
        private static extern IntPtr DyldGetImageVmaddrSlide(uint index);
    }
}
