using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace DeviceTrust.Client.Maui.Android
{
    /// <summary>The result of one in-memory versus on-disk code comparison.</summary>
    public sealed class CodeIntegrityMeasurement
    {
        /// <summary>Whether the comparison ran at all.</summary>
        public bool Checked { get; set; }

        /// <summary>Why it did not run, when <see cref="Checked"/> is false.</summary>
        public string Reason { get; set; } = string.Empty;

        /// <summary>Bytes compared in the core bucket (libc, libart).</summary>
        public long CoreComparedBytes { get; set; }

        /// <summary>Bytes that differ in the core bucket.</summary>
        public long CoreDiffBytes { get; set; }

        /// <summary>Bytes compared in the extended system bucket.</summary>
        public long ExtComparedBytes { get; set; }

        /// <summary>Bytes that differ in the extended system bucket.</summary>
        public long ExtDiffBytes { get; set; }

        /// <summary>How many extended libraries differ.</summary>
        public int ExtLibrariesDiffering { get; set; }

        /// <summary>Bytes compared in the application's own bucket.</summary>
        public long AppComparedBytes { get; set; }

        /// <summary>Bytes that differ in the application's own bucket.</summary>
        public long AppDiffBytes { get; set; }

        /// <summary>How many application libraries differ.</summary>
        public int AppLibrariesDiffering { get; set; }

        /// <summary>The names of every library that differs, comma separated.</summary>
        public string DiffedLibraries { get; set; } = string.Empty;

        /// <summary>
        /// How many execute-only mappings had to have PROT_READ added, and
        /// restored, to be compared at all.
        /// </summary>
        public int ExecuteOnlyRegionsUnlocked { get; set; }

        /// <summary>
        /// How many execute-only mappings could not be made readable and were
        /// therefore not compared. A non-zero value here means the buckets are
        /// incomplete, which is a different statement from "clean".
        /// </summary>
        public int ExecuteOnlyRegionsUnreadable { get; set; }
    }

    /// <summary>
    /// Compares the executable pages mapped into this process against the same
    /// bytes on disk, entirely in managed code.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the purest structural hook detector available to a client. An
    /// inline hook overwrites a function prologue, so the executable segment in
    /// memory diverges from the file it was loaded from. It compares bytes rather
    /// than recognising a framework, so it catches any inline hooker — Frida, or
    /// a bespoke library such as Dobby — and a rename does not help the attacker
    /// at all.
    /// </para>
    /// <para>
    /// The reference Android implementation needed an NDK component for this,
    /// because Kotlin cannot dereference an arbitrary address and SELinux denies
    /// <c>untrusted_app</c> access to <c>/proc/self/mem</c>. .NET needs no such
    /// component: <c>/proc/self/maps</c> is an ordinary file read, and
    /// <see cref="Marshal.Copy(IntPtr, byte[], int, int)"/> reads this process's
    /// own already-mapped, readable pages by pointer. No JNI, no native library,
    /// nothing extra to package or to keep in step with the managed code.
    /// </para>
    /// <para>
    /// Two details are load-bearing, both learned the expensive way in the
    /// reference implementation and reproduced here deliberately:
    /// </para>
    /// <para>
    /// <b>Every executable VMA of a library is compared, not just the first.</b>
    /// An inline hooker flips individual code pages writable to patch them, which
    /// splits a library's single <c>r-x</c> mapping into several, and the patched
    /// page is usually not the first one. A single-VMA version compared 114 KB of
    /// libc and reported zero against a live hook — a false negative.
    /// </para>
    /// <para>
    /// <b>The ART JIT code cache is excluded.</b> It legitimately presents as
    /// executable and <c>(deleted)</c>. Without that exclusion every clean device
    /// is a false positive.
    /// </para>
    /// <para>
    /// A bucket reporting <c>compared_bytes = 0</c> is <b>inert, not clean</b>.
    /// That distinction shipped as a defect once in the reference implementation
    /// and was caught only by reading the raw numbers, so the caller must check
    /// it before letting a bucket score anything.
    /// </para>
    /// </remarks>
    public static class ManagedCodeIntegrity
    {
        /// <summary>Per-library ceiling, matching the reference implementation's 4 MiB cap.</summary>
        public const int MaxBytesPerLibrary = 4 * 1024 * 1024;

        private const int ProtRead = 0x1;
        private const int ProtExec = 0x4;

        [DllImport("libc", SetLastError = true, EntryPoint = "mprotect")]
        private static extern int Mprotect(IntPtr address, IntPtr length, int protection);

        private static readonly string[] CoreLibraries = { "libc.so", "libart.so" };

        // TLS is the notable member: certificate-pinning bypasses patch libssl and
        // libcrypto, which makes them a high-value target and worth measuring even
        // though they are outside the core pair.
        private static readonly string[] ExtLibraries =
        {
            "libc++.so", "libssl.so", "libcrypto.so", "libandroid_runtime.so", "libbinder.so",
        };

        // A .NET Android release build maps its native code straight out of the
        // APK unless extractNativeLibs is on, so the app bucket has to accept a
        // .apk backing file as well as a .so. The reference implementation's app
        // bucket read compared_bytes=0 — inert — until it did the same.
        private static readonly string[] AppPathPrefixes = { "/data/app/", "/data/data/", "/data/user/" };

        /// <summary>Runs the comparison over this process's own mappings.</summary>
        public static CodeIntegrityMeasurement Measure()
        {
            var measurement = new CodeIntegrityMeasurement();

            List<MemoryRegion> regions;
            try
            {
                regions = ReadExecutableRegions();
            }
            catch (IOException error)
            {
                measurement.Reason = "maps_unreadable:" + error.GetType().Name;
                return measurement;
            }
            catch (UnauthorizedAccessException error)
            {
                measurement.Reason = "maps_unreadable:" + error.GetType().Name;
                return measurement;
            }

            if (regions.Count == 0)
            {
                measurement.Reason = "no_executable_mappings";
                return measurement;
            }

            var differing = new List<string>();
            var unlocked = 0;
            var unlockFailed = 0;

            foreach (var library in regions.GroupBy(region => region.Path, StringComparer.Ordinal))
            {
                var bucket = ClassifyBucket(library.Key);
                if (bucket == Bucket.Ignored)
                {
                    continue;
                }

                var comparison = CompareLibrary(library.Key, library.ToList(), ref unlocked, ref unlockFailed);
                if (comparison.ComparedBytes == 0)
                {
                    continue;
                }

                var name = Path.GetFileName(library.Key);
                if (comparison.DiffBytes > 0 && !differing.Contains(name, StringComparer.Ordinal))
                {
                    differing.Add(name);
                }

                switch (bucket)
                {
                    case Bucket.Core:
                        measurement.CoreComparedBytes += comparison.ComparedBytes;
                        measurement.CoreDiffBytes += comparison.DiffBytes;
                        break;
                    case Bucket.Extended:
                        measurement.ExtComparedBytes += comparison.ComparedBytes;
                        measurement.ExtDiffBytes += comparison.DiffBytes;
                        if (comparison.DiffBytes > 0)
                        {
                            measurement.ExtLibrariesDiffering++;
                        }

                        break;
                    case Bucket.Application:
                        measurement.AppComparedBytes += comparison.ComparedBytes;
                        measurement.AppDiffBytes += comparison.DiffBytes;
                        if (comparison.DiffBytes > 0)
                        {
                            measurement.AppLibrariesDiffering++;
                        }

                        break;
                }
            }

            measurement.Checked = true;
            measurement.DiffedLibraries = string.Join(",", differing);
            measurement.ExecuteOnlyRegionsUnlocked = unlocked;
            measurement.ExecuteOnlyRegionsUnreadable = unlockFailed;
            return measurement;
        }

        private static (long ComparedBytes, long DiffBytes) CompareLibrary(
            string path,
            IReadOnlyList<MemoryRegion> regions,
            ref int unlocked,
            ref int unlockFailed)
        {
            long compared = 0;
            long different = 0;

            FileStream file;
            try
            {
                file = File.OpenRead(path);
            }
            catch (Exception)
            {
                // A mapping whose backing file this process cannot read yields no
                // measurement. Reporting it as clean would be a lie; it simply
                // does not contribute to either total.
                return (0, 0);
            }

            using (file)
            {
                var fileLength = file.Length;

                // Ordering by address keeps the per-library budget spent on the
                // library's own layout rather than on whatever /proc happened to
                // list first.
                foreach (var region in regions.OrderBy(item => item.Start))
                {
                    if (compared >= MaxBytesPerLibrary)
                    {
                        break;
                    }

                    var regionLength = (long)(region.End - region.Start);
                    var budget = Math.Min(regionLength, MaxBytesPerLibrary - compared);
                    if (budget <= 0 || region.Offset >= fileLength)
                    {
                        continue;
                    }

                    var available = Math.Min(budget, fileLength - region.Offset);
                    if (available <= 0)
                    {
                        continue;
                    }

                    var length = (int)Math.Min(available, int.MaxValue);
                    var fromDisk = new byte[length];
                    var fromMemory = new byte[length];

                    // Android 10 maps system libraries execute-only ("--xp"), so
                    // the pages cannot simply be read: on the Huawei AQM-LX1, 283
                    // of 336 executable mappings are execute-only, including every
                    // core and ext target. Reading one without lifting the
                    // protection first segfaults the process, and skipping it
                    // silently is worse -- the bucket then reports compared=0,
                    // which looks identical to "clean" in the score. Add PROT_READ
                    // for the duration of the copy and restore it immediately.
                    var needsUnlock = !region.Readable;
                    var regionLengthNative = (IntPtr)(long)(region.End - region.Start);
                    if (needsUnlock)
                    {
                        if (Mprotect((IntPtr)region.Start, regionLengthNative, ProtRead | ProtExec) != 0)
                        {
                            unlockFailed++;
                            continue;
                        }

                        unlocked++;
                    }

                    try
                    {
                        file.Seek(region.Offset, SeekOrigin.Begin);
                        var read = ReadExactly(file, fromDisk, length);
                        if (read <= 0)
                        {
                            continue;
                        }

                        // Reading this process's own mapped pages by pointer. This
                        // is the step SELinux denies through /proc/self/mem and
                        // permits here, which is why no NDK component is needed.
                        Marshal.Copy((IntPtr)region.Start, fromMemory, 0, read);

                        compared += read;
                        for (var index = 0; index < read; index++)
                        {
                            if (fromDisk[index] != fromMemory[index])
                            {
                                different++;
                            }
                        }
                    }
                    catch (Exception)
                    {
                        // A mapping that vanished between reading /proc/self/maps
                        // and reading it contributes nothing rather than failing
                        // the whole probe.
                    }
                    finally
                    {
                        if (needsUnlock)
                        {
                            // Put the page back exactly as it was found. Leaving
                            // libc readable would be a real weakening of the
                            // process, done by the probe that exists to detect
                            // exactly that kind of change.
                            Mprotect((IntPtr)region.Start, regionLengthNative, ProtExec);
                        }
                    }
                }
            }

            return (compared, different);
        }

        private static int ReadExactly(Stream stream, byte[] buffer, int count)
        {
            var total = 0;
            while (total < count)
            {
                var read = stream.Read(buffer, total, count - total);
                if (read <= 0)
                {
                    break;
                }

                total += read;
            }

            return total;
        }

        private static Bucket ClassifyBucket(string path)
        {
            var name = Path.GetFileName(path);

            if (CoreLibraries.Any(candidate => string.Equals(name, candidate, StringComparison.Ordinal)))
            {
                return Bucket.Core;
            }

            if (ExtLibraries.Any(candidate => string.Equals(name, candidate, StringComparison.Ordinal)))
            {
                return Bucket.Extended;
            }

            if (AppPathPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal)))
            {
                return Bucket.Application;
            }

            return Bucket.Ignored;
        }

        private static List<MemoryRegion> ReadExecutableRegions()
        {
            var regions = new List<MemoryRegion>();

            foreach (var line in File.ReadAllLines("/proc/self/maps"))
            {
                var parts = line.Split(new[] { ' ' }, 6, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 6)
                {
                    continue;
                }

                var permissions = parts[1];
                if (permissions.Length < 4 || permissions[2] != 'x')
                {
                    continue;
                }

                // Writable-and-executable pages are not compared: there is no
                // stable on-disk image to compare them against. The exec_mappings
                // probe is what reports those.
                if (permissions[1] == 'w')
                {
                    continue;
                }

                var path = parts[5].Trim();
                if (path.Length == 0 || path[0] == '[' || IsExcluded(path))
                {
                    continue;
                }

                var bounds = parts[0].Split('-');
                if (bounds.Length != 2
                    || !ulong.TryParse(bounds[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var start)
                    || !ulong.TryParse(bounds[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var end)
                    || !long.TryParse(parts[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset)
                    || end <= start)
                {
                    continue;
                }

                regions.Add(new MemoryRegion(start, end, offset, path, permissions[0] == 'r'));
            }

            return regions;
        }

        private static bool IsExcluded(string path)
        {
            if (path.Contains("(deleted)", StringComparison.Ordinal))
            {
                return true;
            }

            var lower = path.ToLowerInvariant();

            // The ART JIT code cache is executable and file-backed by a deleted
            // memfd on every clean device. Comparing it is meaningless — there is
            // nothing on disk to compare against — and counting it makes the whole
            // fleet a false positive.
            return lower.Contains("jit-cache", StringComparison.Ordinal)
                   || lower.Contains("jit-zygote", StringComparison.Ordinal)
                   || lower.Contains("dalvik-", StringComparison.Ordinal)
                   || lower.StartsWith("/memfd:", StringComparison.Ordinal)
                   || lower.StartsWith("/dev/ashmem", StringComparison.Ordinal)
                   || lower.StartsWith("/dev/", StringComparison.Ordinal)
                   || lower.StartsWith("anon", StringComparison.Ordinal);
        }

        private enum Bucket
        {
            Ignored,
            Core,
            Extended,
            Application,
        }

        private readonly struct MemoryRegion
        {
            public MemoryRegion(ulong start, ulong end, long offset, string path, bool readable)
            {
                Start = start;
                End = end;
                Offset = offset;
                Path = path;
                Readable = readable;
            }

            public ulong Start { get; }

            public ulong End { get; }

            public long Offset { get; }

            public string Path { get; }

            /// <summary>False for an Android 10+ execute-only ("--xp") mapping.</summary>
            public bool Readable { get; }
        }
    }
}
