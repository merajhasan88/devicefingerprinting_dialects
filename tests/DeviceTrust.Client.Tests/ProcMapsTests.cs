using System.Linq;
using DeviceTrust.Client.Integrity;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Tests for maps parsing and the executable-memory summary.
    /// </summary>
    /// <remarks>
    /// The fixture lines below are the real shapes captured from a Huawei
    /// AQM-LX1 running the .NET harness: Mono's writable-and-executable code
    /// manager chunks, ART's JIT cache mapped three times over one memfd,
    /// Android 10's execute-only system libraries, and the app's own readable
    /// executable code. Each of those has caused a defect at some point, which is
    /// why they are pinned here rather than only exercised on a handset.
    /// </remarks>
    public sealed class ProcMapsTests
    {
        private static readonly string[] HuaweiSample =
        {
            // Mono's code manager: anonymous, no backing file, writable AND executable.
            "7999b0b000-7999b1b000 rwxp 00000000 00:00 0",
            "7999b82000-7999b92000 rwxp 00000000 00:00 0",
            // ART's JIT code cache: one memfd, three separate views, never rwx.
            "79a0000000-79a2000000 rw-s 00000000 00:05 12345  /memfd:/jit-cache (deleted)",
            "79a2000000-79a4000000 r-xs 02000000 00:05 12345  /memfd:/jit-cache (deleted)",
            "79a4000000-79a6000000 r--s 04000000 00:05 12345  /memfd:/jit-cache (deleted)",
            // Android 10 maps system libraries execute-only.
            "79b0000000-79b0100000 --xp 00002000 fe:09 1001  /apex/com.android.runtime/lib64/bionic/libc.so",
            "79b1000000-79b1100000 --xp 00002000 fe:09 1002  /system/lib64/libc++.so",
            // The app's own native code stays readable.
            "79c0000000-79c0080000 r-xp 00001000 fe:09 2001  /data/app/com.example.devicefingerprinting_dotnet-x==/lib/arm64/libSystem.Native.so",
            // Ordinary non-executable data.
            "79d0000000-79d0010000 rw-p 00000000 00:00 0",
        };

        [Fact]
        public void TryParse_ReadsEveryField()
        {
            Assert.True(ProcMapsParser.TryParse(
                "79c0000000-79c0080000 r-xp 00001000 fe:09 2001  /data/app/x/lib/arm64/lib.so",
                out var entry));

            Assert.Equal(0x79c0000000UL, entry.Start);
            Assert.Equal(0x79c0080000UL, entry.End);
            Assert.Equal("r-xp", entry.Permissions);
            Assert.Equal(0x1000, entry.Offset);
            Assert.Equal("2001", entry.Inode);
            Assert.Equal("/data/app/x/lib/arm64/lib.so", entry.Path);
            Assert.Equal(0x80000, entry.Length);
            Assert.True(entry.Readable);
            Assert.False(entry.Writable);
            Assert.True(entry.Executable);
        }

        [Fact]
        public void TryParse_KeepsADeletedSuffixWithThePath()
        {
            // The pathname field can contain spaces. Splitting it away would make
            // a memfd JIT mapping unrecognisable.
            Assert.True(ProcMapsParser.TryParse(
                "79a0000000-79a2000000 rw-s 00000000 00:05 12345  /memfd:/jit-cache (deleted)",
                out var entry));

            Assert.Equal("/memfd:/jit-cache (deleted)", entry.Path);
        }

        [Fact]
        public void TryParse_RecognisesExecuteOnlyMappings()
        {
            Assert.True(ProcMapsParser.TryParse(
                "79b0000000-79b0100000 --xp 00002000 fe:09 1001  /x/libc.so", out var entry));

            Assert.False(entry.Readable);
            Assert.True(entry.Executable);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("garbage")]
        [InlineData("zzzz-yyyy rwxp 0 00:00 0")]
        [InlineData("7999b0b000 rwxp 00000000 00:00 0")]
        public void TryParse_RejectsMalformedLines(string line)
        {
            Assert.False(ProcMapsParser.TryParse(line, out _));
        }

        [Fact]
        public void Summarise_CountsOnlyTrulyWritableExecutableMappings()
        {
            var summary = ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(HuaweiSample));

            // The two Mono chunks, and nothing else. The JIT cache must not be
            // counted: no single view of it is both writable and executable.
            Assert.Equal(2, summary.WritableExecutableCount);
            Assert.Equal(2 * 0x10000, summary.WritableExecutableBytes);
            Assert.Equal(2, summary.WritableExecutableUnlabelled);
            Assert.Equal(0, summary.WritableExecutableFileBacked);
            Assert.Equal(0, summary.WritableExecutableLabelled);
        }

        [Fact]
        public void Summarise_SeesTheDualMappedJitCache()
        {
            var summary = ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(HuaweiSample));

            // The JIT cache is runtime-generated code mapped writably and
            // executably through separate views: the signature of a runtime that
            // separates write from execute, which is what ART does and Mono does
            // not.
            Assert.Equal(1, summary.DualMappedRuntimeCodeRegions);
        }

        [Fact]
        public void Summarise_DoesNotCountOrdinaryLibrariesAsRuntimeCode()
        {
            // Every shared library has a writable data segment and an executable
            // text segment, so counting "any file mapped both ways" reports a few
            // hundred on a real device and says nothing about a JIT. Only the
            // memfd/ashmem/deleted case is runtime-generated code.
            var lines = new[]
            {
                "79c0000000-79c0080000 r-xp 00001000 fe:09 2001  /system/lib64/libfoo.so",
                "79c0080000-79c0090000 rw-p 00081000 fe:09 2001  /system/lib64/libfoo.so",
            };

            var summary = ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(lines));

            Assert.Equal(1, summary.DualMappedFiles);
            Assert.Equal(0, summary.DualMappedRuntimeCodeRegions);
        }

        [Fact]
        public void Summarise_ReportsSizeClassesLargestFirst()
        {
            var lines = HuaweiSample.Concat(new[]
            {
                "7999c00000-7999c04000 rwxp 00000000 00:00 0",
            }).ToArray();

            var summary = ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(lines));

            Assert.Equal("65536:2,16384:1", summary.WritableExecutableSizeClasses);
            Assert.Equal(0x4000, summary.WritableExecutableSmallestBytes);
            Assert.Equal(0x10000, summary.WritableExecutableLargestBytes);
        }

        [Fact]
        public void Summarise_SeparatesExecuteOnlyFromReadableExecutable()
        {
            var summary = ExecutableMemorySummary.Summarise(ProcMapsParser.ParseAll(HuaweiSample));

            Assert.Equal(2, summary.ExecuteOnlyCount);
            // The app's own library, the JIT's r-xs view, and the two Mono chunks.
            Assert.Equal(4, summary.ReadableExecutableCount);
        }

        [Fact]
        public void Summarise_OfAProcessWithNoExecutableMemoryIsAllZero()
        {
            var summary = ExecutableMemorySummary.Summarise(
                ProcMapsParser.ParseAll(new[] { "79d0000000-79d0010000 rw-p 00000000 00:00 0" }));

            Assert.Equal(0, summary.WritableExecutableCount);
            Assert.Equal(0, summary.WritableExecutableBytes);
            Assert.Equal(string.Empty, summary.WritableExecutableSizeClasses);
            Assert.Equal(0, summary.DualMappedRuntimeCodeRegions);
            Assert.Equal(0, summary.DualMappedFiles);
        }
    }
}
