using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// One measurement of a build's writable-and-executable memory.
    /// </summary>
    /// <remarks>
    /// Deliberately small, so a release pipeline can feed in values parsed from a
    /// device without reconstructing a whole summary object.
    /// </remarks>
    public readonly struct WritableExecutableObservation
    {
        /// <summary>Creates an observation.</summary>
        public WritableExecutableObservation(long bytes, string sizeClasses)
        {
            Bytes = bytes;
            SizeClasses = sizeClasses ?? string.Empty;
        }

        /// <summary>Total writable-and-executable bytes.</summary>
        public long Bytes { get; }

        /// <summary>The <c>bytes:count</c> size classes, as the probe reports them.</summary>
        public string SizeClasses { get; }
    }

    /// <summary>
    /// The writable-and-executable memory a build legitimately reserves, derived
    /// from repeated measurement rather than asserted by hand.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A managed runtime maps writable-and-executable pages by design, so scoring
    /// their presence refuses every device running one. Scoring the <i>excess
    /// over what this build is known to reserve</i> does not, and is the same
    /// shape as <c>code_integrity</c>, which compares against the on-disk image
    /// instead of asking whether executable memory exists at all.
    /// </para>
    /// <para>
    /// The number has to come from measurement because it belongs to the runtime,
    /// not to anything a developer can read off a design document. Measured on
    /// two vendors and two Android versions, .NET 8 with Mono reserved exactly
    /// 1,114,112 bytes — 17 blocks of 64 KiB — on every run, while the region
    /// <i>count</i> varied between 12 and 17 because the kernel coalesces
    /// adjacent mappings differently. That is why the total is the invariant and
    /// the count is not, and why deriving a baseline refuses to emit one
    /// from observations whose totals disagree.
    /// </para>
    /// <para>
    /// This runs on a build machine against a device, never on a user's device as
    /// part of scoring. A baseline a client could assert about itself would be
    /// worthless: the process under suspicion would simply claim a large one.
    /// </para>
    /// </remarks>
    public sealed class WritableExecutableBaseline
    {
        private WritableExecutableBaseline(long bytes, long granularity, int observations, int smallestRegionBytes)
        {
            Bytes = bytes;
            Granularity = granularity;
            Observations = observations;
            SmallestRegionBytes = smallestRegionBytes;
        }

        /// <summary>The reserved total, in bytes, that every observation agreed on.</summary>
        public long Bytes { get; }

        /// <summary>
        /// The allocation granularity every observed region size is a multiple of.
        /// </summary>
        /// <remarks>
        /// A size that is not a multiple of this is a different allocator, which
        /// is how a Frida gadget shows up: its 4 KiB and 28 KiB regions are not
        /// multiples of Mono's 64 KiB.
        /// </remarks>
        public long Granularity { get; }

        /// <summary>How many measurements agreed.</summary>
        public int Observations { get; }

        /// <summary>The smallest region seen, which is normally the granularity itself.</summary>
        public int SmallestRegionBytes { get; }

        /// <summary>Why a baseline could not be derived, when one could not.</summary>
        public string? Rejection { get; private init; }

        /// <summary>Whether a baseline was derived.</summary>
        public bool IsUsable => Rejection is null;

        /// <summary>
        /// Derives a baseline from repeated measurements of the same build.
        /// </summary>
        /// <param name="observations">One summary per cold start.</param>
        /// <param name="minimumObservations">
        /// How many runs must agree. Two is not enough to distinguish a stable
        /// total from a coincidence, so the default is four.
        /// </param>
        public static WritableExecutableBaseline Compute(
            IReadOnlyList<ExecutableMemorySummary> observations,
            int minimumObservations = 4)
        {
            if (observations is null)
            {
                throw new ArgumentNullException(nameof(observations));
            }

            return Compute(
                observations
                    .Select(item => new WritableExecutableObservation(
                        item.WritableExecutableBytes,
                        item.WritableExecutableSizeClasses))
                    .ToList(),
                minimumObservations);
        }

        /// <summary>Derives a baseline from measurements parsed off a device.</summary>
        public static WritableExecutableBaseline Compute(
            IReadOnlyList<WritableExecutableObservation> observations,
            int minimumObservations = 4)
        {
            if (observations is null)
            {
                throw new ArgumentNullException(nameof(observations));
            }

            if (observations.Count < minimumObservations)
            {
                return Reject(
                    "only " + observations.Count.ToString(CultureInfo.InvariantCulture)
                    + " observation(s); at least " + minimumObservations.ToString(CultureInfo.InvariantCulture)
                    + " are required for a baseline to mean anything");
            }

            var totals = observations.Select(item => item.Bytes).Distinct().ToList();
            if (totals.Count != 1)
            {
                // Emitting the maximum here would be the tempting mistake: it
                // would produce a baseline that silently tolerates whatever
                // variation was present, including a compromise that happened to
                // be running during measurement.
                return Reject(
                    "the reserved total was not stable across runs ("
                    + string.Join(", ", totals.OrderBy(value => value)
                        .Select(value => value.ToString(CultureInfo.InvariantCulture)))
                    + "); measure again on an idle device, and do not average them");
            }

            var total = totals[0];
            if (total <= 0)
            {
                return Reject("no writable-and-executable memory was observed, so there is nothing to baseline");
            }

            var sizes = new List<long>();
            foreach (var observation in observations)
            {
                foreach (var entry in ParseSizeClasses(observation.SizeClasses))
                {
                    sizes.Add(entry);
                }
            }

            if (sizes.Count == 0)
            {
                return Reject("no region sizes were reported, so the granularity cannot be derived");
            }

            var granularity = sizes.Aggregate(GreatestCommonDivisor);
            if (granularity <= 0 || total % granularity != 0)
            {
                return Reject(
                    "the reserved total " + total.ToString(CultureInfo.InvariantCulture)
                    + " is not a whole number of " + granularity.ToString(CultureInfo.InvariantCulture)
                    + "-byte blocks, so the observations are not self-consistent");
            }

            return new WritableExecutableBaseline(
                total,
                granularity,
                observations.Count,
                (int)Math.Min(int.MaxValue, sizes.Min()));
        }

        /// <summary>Renders the baseline as the server environment settings that pin it.</summary>
        public string ToEnvironmentSettings(string apkSha256)
        {
            if (!IsUsable)
            {
                throw new InvalidOperationException("No baseline was derived: " + Rejection);
            }

            return "INTEGRITY_ANDROID_APK_SHA256=" + apkSha256 + Environment.NewLine
                   + "INTEGRITY_ANDROID_WX_BASELINE_BYTES=" + Bytes.ToString(CultureInfo.InvariantCulture)
                   + Environment.NewLine
                   + "INTEGRITY_ANDROID_WX_GRANULARITY=" + Granularity.ToString(CultureInfo.InvariantCulture);
        }

        private static IEnumerable<long> ParseSizeClasses(string sizeClasses)
        {
            if (string.IsNullOrEmpty(sizeClasses))
            {
                yield break;
            }

            foreach (var pair in sizeClasses.Split(','))
            {
                var separator = pair.IndexOf(':');
                var text = separator < 0 ? pair : pair.Substring(0, separator);
                if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var size)
                    && size > 0)
                {
                    yield return size;
                }
            }
        }

        private static long GreatestCommonDivisor(long left, long right)
        {
            while (right != 0)
            {
                (left, right) = (right, left % right);
            }

            return Math.Abs(left);
        }

        private static WritableExecutableBaseline Reject(string reason)
        {
            return new WritableExecutableBaseline(0, 0, 0, 0) { Rejection = reason };
        }
    }
}
