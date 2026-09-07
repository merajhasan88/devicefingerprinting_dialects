using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// Characterises the executable memory in a process, in enough detail for a
    /// server to compare a report against a known-good baseline for the same
    /// build.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is measurement, not judgement. The client computes no verdict and no
    /// score; it reports counts, byte totals and shapes, and the server decides
    /// what they mean.
    /// </para>
    /// <para>
    /// <b>Why the extra detail exists.</b> Scoring writable-and-executable memory
    /// by mere presence gives a clean .NET Android device
    /// <c>android_wx_memory +60</c> and refuses it at the gate, because Mono's
    /// code manager maps such pages by design. ART, in the same process, has a
    /// JIT and maps none — it keeps write and execute in separate views of one
    /// memfd. So "is any W^X memory present" does not separate a healthy runtime
    /// from an unhealthy one; the shape of it might.
    /// </para>
    /// <para>
    /// <b>What this cannot do.</b> An attacker who controls the process can make
    /// their allocation look exactly like the runtime's, and can edit this report
    /// before it is signed. None of these fields are attestation. They are useful
    /// for the same reason <c>code_integrity</c> is useful: they let a server
    /// compare against what this build is known to look like, rather than against
    /// an absolute that no managed runtime can meet.
    /// </para>
    /// </remarks>
    public sealed class ExecutableMemorySummary
    {
        private ExecutableMemorySummary()
        {
        }

        /// <summary>Mappings that are writable and executable at once.</summary>
        public int WritableExecutableCount { get; private set; }

        /// <summary>Total bytes that are writable and executable at once.</summary>
        public long WritableExecutableBytes { get; private set; }

        /// <summary>How many of those carry no name and no backing file.</summary>
        public int WritableExecutableUnlabelled { get; private set; }

        /// <summary>How many carry an <c>[anon:…]</c> label.</summary>
        public int WritableExecutableLabelled { get; private set; }

        /// <summary>How many are backed by a file.</summary>
        public int WritableExecutableFileBacked { get; private set; }

        /// <summary>The smallest writable-executable mapping, in bytes.</summary>
        public long WritableExecutableSmallestBytes { get; private set; }

        /// <summary>The largest writable-executable mapping, in bytes.</summary>
        public long WritableExecutableLargestBytes { get; private set; }

        /// <summary>
        /// The distinct sizes of the writable-executable mappings and how many of
        /// each, as <c>bytes:count</c> pairs, largest first.
        /// </summary>
        /// <remarks>
        /// The most useful single field for baselining. Mono allocates uniform
        /// chunks, so a healthy build has a short, stable list; a new size class
        /// appearing is a change worth looking at even when the count is
        /// unremarkable.
        /// </remarks>
        public string WritableExecutableSizeClasses { get; private set; } = string.Empty;

        /// <summary>
        /// How many distinct backing files are mapped both writably and
        /// executably through separate mappings.
        /// </summary>
        /// <remarks>
        /// Mostly uninteresting on its own: every loaded ELF object contributes
        /// one, because a shared library has a writable data segment and an
        /// executable text segment. A real device reports a few hundred. Kept
        /// because it is the denominator for the field below.
        /// </remarks>
        public int DualMappedFiles { get; private set; }

        /// <summary>
        /// How many dual-mapped regions are <b>runtime-generated code</b> rather
        /// than on-disk ELF objects — a memfd, an ashmem region, or a deleted
        /// backing file mapped both writably and executably through separate
        /// mappings.
        /// </summary>
        /// <remarks>
        /// This is the one that means something. It is the signature of a JIT
        /// that respects W^X: ART maps its code cache several times over one
        /// memfd, writing through one view and executing through another, and so
        /// contributes nothing to <see cref="WritableExecutableCount"/>. A
        /// process showing runtime-generated code with a non-zero
        /// writable-executable count has at least one allocator that does not
        /// separate the two.
        /// </remarks>
        public int DualMappedRuntimeCodeRegions { get; private set; }

        /// <summary>Executable mappings that are readable, the ordinary case.</summary>
        public int ReadableExecutableCount { get; private set; }

        /// <summary>
        /// Executable mappings that cannot be read at all.
        /// </summary>
        /// <remarks>
        /// Android 10 and later map system libraries execute-only. A high count
        /// here is normal on those releases and explains why a code-integrity
        /// bucket would read as inert without lifting the protection first.
        /// </remarks>
        public int ExecuteOnlyCount { get; private set; }

        private static bool IsRuntimeGeneratedCode(string path)
        {
            // A memfd, an ashmem region or a deleted backing file: memory the
            // process produced at runtime rather than an object loaded from disk.
            return path.StartsWith("/memfd:", StringComparison.Ordinal)
                   || path.StartsWith("/dev/ashmem", StringComparison.Ordinal)
                   || path.Contains("(deleted)", StringComparison.Ordinal);
        }

        /// <summary>Summarises a parsed maps table.</summary>
        public static ExecutableMemorySummary Summarise(IReadOnlyList<ProcMapsEntry> entries)
        {
            if (entries is null)
            {
                throw new ArgumentNullException(nameof(entries));
            }

            var summary = new ExecutableMemorySummary();
            var sizes = new Dictionary<long, int>();
            var writablePaths = new HashSet<string>(StringComparer.Ordinal);
            var executablePaths = new HashSet<string>(StringComparer.Ordinal);
            var runtimeCodePaths = new HashSet<string>(StringComparer.Ordinal);

            foreach (var entry in entries)
            {
                if (entry.Path.Length > 0)
                {
                    if (entry.Writable && !entry.Executable)
                    {
                        writablePaths.Add(entry.Path);
                    }

                    if (entry.Executable && !entry.Writable)
                    {
                        executablePaths.Add(entry.Path);
                    }

                    if (IsRuntimeGeneratedCode(entry.Path))
                    {
                        runtimeCodePaths.Add(entry.Path);
                    }
                }

                if (!entry.Executable)
                {
                    continue;
                }

                if (entry.Readable)
                {
                    summary.ReadableExecutableCount++;
                }
                else
                {
                    summary.ExecuteOnlyCount++;
                }

                if (!entry.Writable)
                {
                    continue;
                }

                summary.WritableExecutableCount++;
                summary.WritableExecutableBytes += entry.Length;
                sizes[entry.Length] = sizes.TryGetValue(entry.Length, out var seen) ? seen + 1 : 1;

                if (entry.IsLabelledAnonymous)
                {
                    summary.WritableExecutableLabelled++;
                }
                else if (entry.IsUnlabelledAnonymous)
                {
                    summary.WritableExecutableUnlabelled++;
                }
                else
                {
                    summary.WritableExecutableFileBacked++;
                }
            }

            writablePaths.IntersectWith(executablePaths);
            summary.DualMappedFiles = writablePaths.Count;
            writablePaths.IntersectWith(runtimeCodePaths);
            summary.DualMappedRuntimeCodeRegions = writablePaths.Count;

            if (sizes.Count > 0)
            {
                summary.WritableExecutableSmallestBytes = sizes.Keys.Min();
                summary.WritableExecutableLargestBytes = sizes.Keys.Max();
                summary.WritableExecutableSizeClasses = string.Join(
                    ",",
                    sizes.OrderByDescending(pair => pair.Key)
                        .Take(12)
                        .Select(pair => pair.Key.ToString(CultureInfo.InvariantCulture)
                                        + ":" + pair.Value.ToString(CultureInfo.InvariantCulture)));
            }

            return summary;
        }
    }
}
