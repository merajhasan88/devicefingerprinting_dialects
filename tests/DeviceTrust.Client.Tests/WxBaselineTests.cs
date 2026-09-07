using System.Collections.Generic;
using System.Linq;
using DeviceTrust.Client.Integrity;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Tests for deriving a build's writable-executable baseline.
    /// </summary>
    /// <remarks>
    /// The figures are the ones measured on real hardware: .NET 8 with Mono
    /// reserved 1,114,112 bytes — 17 blocks of 64 KiB — identically on a Huawei
    /// AQM-LX1 (Android 10) and an OPPO CPH2083 (Android 9) across sixteen cold
    /// starts, while the region count varied between 12 and 17 as the kernel
    /// coalesced adjacent mappings differently.
    /// </remarks>
    public sealed class WxBaselineTests
    {
        private static ExecutableMemorySummary Observation(params string[] maps)
        {
            return ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(maps));
        }

        private static string[] MonoLike(int sixtyFourKilobyteBlocks, int coalescedPairs = 0)
        {
            // Produces the shape Mono actually has: a fixed reserved total split
            // into a varying number of regions, some of which the kernel merged.
            var lines = new List<string>();
            ulong address = 0x700000000;
            for (var i = 0; i < coalescedPairs; i++)
            {
                lines.Add(Region(ref address, 0x20000));
                sixtyFourKilobyteBlocks -= 2;
            }

            for (var i = 0; i < sixtyFourKilobyteBlocks; i++)
            {
                lines.Add(Region(ref address, 0x10000));
            }

            return lines.ToArray();
        }

        private static string Region(ref ulong address, ulong size)
        {
            var line = address.ToString("x") + "-" + (address + size).ToString("x") + " rwxp 00000000 00:00 0";
            address += size + 0x1000;
            return line;
        }

        [Fact]
        public void Compute_DerivesTheMeasuredBaseline()
        {
            // Seventeen 64 KiB blocks, coalesced differently each run, exactly as
            // the two handsets reported.
            var observations = new[]
            {
                Observation(MonoLike(17)),
                Observation(MonoLike(17, coalescedPairs: 1)),
                Observation(MonoLike(17, coalescedPairs: 2)),
                Observation(MonoLike(17, coalescedPairs: 1)),
            };

            var baseline = WritableExecutableBaseline.Compute(observations);

            Assert.True(baseline.IsUsable, baseline.Rejection);
            Assert.Equal(1_114_112, baseline.Bytes);
            Assert.Equal(65_536, baseline.Granularity);
            Assert.Equal(4, baseline.Observations);
        }

        [Fact]
        public void Compute_RefusesWhenTheTotalIsNotStable()
        {
            // Averaging or taking the maximum would produce a baseline that
            // tolerates whatever was running during measurement, including a
            // compromise. Refusing is the only safe answer.
            var observations = new[]
            {
                Observation(MonoLike(17)),
                Observation(MonoLike(17)),
                Observation(MonoLike(19)),
                Observation(MonoLike(17)),
            };

            var baseline = WritableExecutableBaseline.Compute(observations);

            Assert.False(baseline.IsUsable);
            Assert.Contains("not stable", baseline.Rejection!, System.StringComparison.Ordinal);
            Assert.Throws<System.InvalidOperationException>(() => baseline.ToEnvironmentSettings("abc"));
        }

        [Fact]
        public void Compute_RefusesTooFewObservations()
        {
            var baseline = WritableExecutableBaseline.Compute(new[] { Observation(MonoLike(17)) });

            Assert.False(baseline.IsUsable);
            Assert.Contains("at least 4", baseline.Rejection!, System.StringComparison.Ordinal);
        }

        [Fact]
        public void Compute_RefusesAProcessWithNoWritableExecutableMemory()
        {
            // A Dart AOT build has none. There is nothing to baseline, and
            // emitting zero would look like a valid allowance.
            var clean = Observation("700000000-700010000 r-xp 00000000 fe:09 1  /system/lib64/libfoo.so");
            var baseline = WritableExecutableBaseline.Compute(Enumerable.Repeat(clean, 4).ToList());

            Assert.False(baseline.IsUsable);
            Assert.Contains("nothing to baseline", baseline.Rejection!, System.StringComparison.Ordinal);
        }

        [Fact]
        public void Compute_DerivesGranularityFromEveryObservedSize()
        {
            var observations = Enumerable.Repeat(Observation(MonoLike(17, coalescedPairs: 3)), 4).ToList();

            var baseline = WritableExecutableBaseline.Compute(observations);

            Assert.True(baseline.IsUsable, baseline.Rejection);
            // 64 KiB and 128 KiB regions share a 64 KiB granularity.
            Assert.Equal(65_536, baseline.Granularity);
        }

        [Fact]
        public void ToEnvironmentSettings_EmitsThePinnedServerConfiguration()
        {
            var observations = Enumerable.Repeat(Observation(MonoLike(17)), 4).ToList();

            var settings = WritableExecutableBaseline.Compute(observations)
                .ToEnvironmentSettings("d0d0d0");

            Assert.Contains("INTEGRITY_ANDROID_APK_SHA256=d0d0d0", settings, System.StringComparison.Ordinal);
            Assert.Contains("INTEGRITY_ANDROID_WX_BASELINE_BYTES=1114112", settings, System.StringComparison.Ordinal);
            Assert.Contains("INTEGRITY_ANDROID_WX_GRANULARITY=65536", settings, System.StringComparison.Ordinal);
        }

        [Fact]
        public void Compute_RejectsAFridaShapedObservation()
        {
            // A gadget adds region sizes that are not multiples of the runtime's
            // granularity, which drags the derived granularity down to 4 KiB and
            // changes the total. Either way the run must not silently become the
            // baseline.
            var withGadget = Observation(MonoLike(17).Concat(new[]
            {
                "710000000-710007000 rwxp 00000000 00:00 0",
                "710010000-710011000 rwxp 00000000 00:00 0",
            }).ToArray());
            var clean = Observation(MonoLike(17));

            var baseline = WritableExecutableBaseline.Compute(
                new[] { clean, clean, withGadget, clean });

            Assert.False(baseline.IsUsable);
            Assert.Contains("not stable", baseline.Rejection!, System.StringComparison.Ordinal);
        }
    }
}
