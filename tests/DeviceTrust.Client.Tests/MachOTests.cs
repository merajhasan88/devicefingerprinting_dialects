using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using DeviceTrust.Client.Integrity;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Tests for the Mach-O reader, against images assembled byte by byte.
    /// </summary>
    /// <remarks>
    /// The iOS folder can only be compiled on macOS, so this is the one place
    /// the code-signature parsing can be proven on the build machine. The
    /// layouts follow the reference Swift collector exactly: little-endian
    /// header and load commands, big-endian fat header and signature blobs, and
    /// the CodeDirectory's identifier at <c>identOffset</c> (offset 20) with the
    /// flags word at offset 12.
    /// </remarks>
    public sealed class MachOTests
    {
        private const string Entitlements =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            + "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            + "<plist version=\"1.0\"><dict>"
            + "<key>application-identifier</key><string>TROLLTROLL.com.example.devicefingerprinting_dotnet</string>"
            + "<key>com.apple.developer.team-identifier</key><string>TROLLTROLL</string>"
            + "<key>get-task-allow</key><true/>"
            + "<key>keychain-access-groups</key><array><string>TROLLTROLL.*</string><string>com.apple.token</string></array>"
            + "</dict></plist>";

        [Fact]
        public void TryParse_ReadsAThinImage()
        {
            var image = MachOImage.TryParse(Build(signed: true));

            Assert.NotNull(image);
            Assert.Equal(0, image!.SliceOffset);
        }

        [Fact]
        public void FindSection_LocatesTextInTheTextSegment()
        {
            var image = MachOImage.TryParse(Build(signed: true))!;

            var text = image.FindSection("__TEXT", "__text");

            Assert.NotNull(text);
            Assert.Equal(0x100004000UL, text!.Value.VirtualAddress);
            Assert.Equal(0x4000, text.Value.FileOffset);
            Assert.Equal(0x1234, text.Value.Size);
            Assert.Null(image.FindSection("__DATA", "__data"));
        }

        [Fact]
        public void ReadCodeSignature_ReturnsTheCodeDirectoryIdentifier()
        {
            var image = MachOImage.TryParse(Build(signed: true))!;

            var signature = image.ReadCodeSignature();

            Assert.NotNull(signature);
            Assert.Null(signature!.ParseError);
            // The CodeDirectory identifier is the bundle id, NOT the
            // TEAMID.bundle form the application-identifier entitlement carries.
            // Reporting the wrong one is the contract bug the handoff describes.
            Assert.Equal("com.example.devicefingerprinting_dotnet", signature.Identifier);
            Assert.Equal(0x20002u, signature.CodeDirectoryFlags);
        }

        [Fact]
        public void ReadCodeSignature_ExposesTheEntitlementsPlist()
        {
            var image = MachOImage.TryParse(Build(signed: true))!;
            var signature = image.ReadCodeSignature()!;

            var entitlements = EntitlementsPlist.TryParse(signature.EntitlementsPlist!);

            Assert.NotNull(entitlements);
            Assert.Equal("TROLLTROLL", entitlements!["com.apple.developer.team-identifier"]);
            Assert.Equal(true, entitlements["get-task-allow"]);
            var groups = Assert.IsType<List<object?>>(entitlements["keychain-access-groups"]);
            Assert.Equal(new object?[] { "TROLLTROLL.*", "com.apple.token" }, groups.ToArray());
        }

        [Fact]
        public void ReadCodeSignature_IsNullForAnUnsignedImage()
        {
            // An unsigned build has no LC_CODE_SIGNATURE at all. Null here is
            // what lets the collector report signed=false honestly instead of
            // reading an absent signature as a clean one.
            var image = MachOImage.TryParse(Build(signed: false))!;

            Assert.Null(image.ReadCodeSignature());
        }

        [Fact]
        public void TryParse_ResolvesTheArm64SliceOfAFatImage()
        {
            var thin = Build(signed: true);
            var fat = WrapFat(thin, arm64Offset: 0x4000);

            var image = MachOImage.TryParse(fat);

            Assert.NotNull(image);
            Assert.Equal(0x4000, image!.SliceOffset);
            // dataoff inside the slice is relative to the slice, so the
            // identifier must still be found once the slice offset is added.
            Assert.Equal("com.example.devicefingerprinting_dotnet", image.ReadCodeSignature()!.Identifier);
            Assert.Equal(0x4000L, image.FindSection("__TEXT", "__text")!.Value.FileOffset);
        }

        [Theory]
        [InlineData(new byte[0])]
        [InlineData(new byte[] { 1, 2, 3, 4 })]
        public void TryParse_RejectsWhatIsNotAMachO(byte[] bytes)
        {
            Assert.Null(MachOImage.TryParse(bytes));
        }

        [Fact]
        public void TryParse_RejectsAByteSwappedImage()
        {
            // MH_CIGAM_64. Every later field would need swapping too; refusing
            // is safer than silently misparsing.
            var bytes = Build(signed: true);
            Array.Reverse(bytes, 0, 4);

            Assert.Null(MachOImage.TryParse(bytes));
        }

        [Fact]
        public void ReadCodeSignature_ReportsABrokenSuperBlobRatherThanGuessing()
        {
            var bytes = Build(signed: true);
            var image = MachOImage.TryParse(bytes)!;
            // Corrupt the SuperBlob magic.
            var signature = image.ReadCodeSignature()!;
            Assert.Null(signature.ParseError);

            var corrupt = Build(signed: true, corruptSuperBlob: true);
            var broken = MachOImage.TryParse(corrupt)!.ReadCodeSignature();

            Assert.NotNull(broken);
            Assert.Equal("Not an embedded signature SuperBlob.", broken!.ParseError);
            Assert.Null(broken.Identifier);
        }

        [Fact]
        public void EntitlementsPlist_RejectsWhatIsNotAPlist()
        {
            Assert.Null(EntitlementsPlist.TryParse(Encoding.UTF8.GetBytes("<html/>")));
            Assert.Null(EntitlementsPlist.TryParse(new byte[] { 0xff, 0xfe }));
            Assert.Null(EntitlementsPlist.TryParse(Array.Empty<byte>()));
        }

        // ------------------------------------------------------------ builder

        /// <summary>
        /// Assembles a minimal but structurally faithful 64-bit Mach-O: one
        /// __TEXT segment holding a __text section, and optionally an
        /// LC_CODE_SIGNATURE pointing at a SuperBlob with a CodeDirectory (slot
        /// 0) and entitlements (slot 5).
        /// </summary>
        private static byte[] Build(bool signed, bool corruptSuperBlob = false)
        {
            const uint LcSegment64 = 0x19;
            const uint LcCodeSignature = 0x1d;
            var commands = new List<byte[]>();

            // LC_SEGMENT_64 __TEXT with one section, __text.
            using (var segment = new MemoryStream())
            using (var w = new BinaryWriter(segment))
            {
                w.Write(LcSegment64);
                w.Write((uint)(72 + 80));
                w.Write(FixedName("__TEXT"));
                w.Write(0x100000000UL);          // vmaddr
                w.Write(0x8000UL);               // vmsize
                w.Write(0UL);                    // fileoff
                w.Write(0x8000UL);               // filesize
                w.Write(5); w.Write(5);          // maxprot, initprot
                w.Write(1u);                     // nsects
                w.Write(0u);                     // flags
                // section_64
                w.Write(FixedName("__text"));
                w.Write(FixedName("__TEXT"));
                w.Write(0x100004000UL);          // addr
                w.Write(0x1234UL);               // size
                w.Write(0x4000u);                // offset
                w.Write(2u);                     // align
                w.Write(0u); w.Write(0u);        // reloff, nreloc
                w.Write(0x80000400u);            // flags
                w.Write(0u); w.Write(0u); w.Write(0u);
                commands.Add(segment.ToArray());
            }

            var headerAndCommands = 32 + 72 + 80 + (signed ? 16 : 0);
            var signatureOffset = 0x6000;
            byte[] superBlob = Array.Empty<byte>();
            if (signed)
            {
                superBlob = BuildSuperBlob(corruptSuperBlob);
                using var command = new MemoryStream();
                using var w = new BinaryWriter(command);
                w.Write(LcCodeSignature);
                w.Write(16u);
                w.Write((uint)signatureOffset);
                w.Write((uint)superBlob.Length);
                commands.Add(command.ToArray());
            }

            var file = new byte[signatureOffset + superBlob.Length + 64];
            using (var stream = new MemoryStream(file))
            using (var w = new BinaryWriter(stream))
            {
                w.Write(0xfeedfacfu);            // MH_MAGIC_64
                w.Write(0x0100000cu);            // CPU_TYPE_ARM64
                w.Write(0u);                     // subtype
                w.Write(2u);                     // MH_EXECUTE
                w.Write((uint)commands.Count);
                w.Write((uint)(headerAndCommands - 32));
                w.Write(0u);                     // flags
                w.Write(0u);                     // reserved
                foreach (var command in commands)
                {
                    w.Write(command);
                }
            }

            Buffer.BlockCopy(superBlob, 0, file, signatureOffset, superBlob.Length);
            return file;
        }

        private static byte[] BuildSuperBlob(bool corrupt)
        {
            var identifier = Encoding.ASCII.GetBytes("com.example.devicefingerprinting_dotnet\0");
            var plist = Encoding.UTF8.GetBytes(Entitlements);

            // CodeDirectory: magic, length, version, flags, hashOffset,
            // identOffset, then the identifier string at identOffset.
            var codeDirectory = new MemoryStream();
            WriteBig(codeDirectory, 0xfade0c02);
            WriteBig(codeDirectory, (uint)(44 + identifier.Length));
            WriteBig(codeDirectory, 0x20400);     // version
            WriteBig(codeDirectory, 0x20002);     // flags
            WriteBig(codeDirectory, 0);           // hashOffset
            WriteBig(codeDirectory, 44);          // identOffset
            for (var i = 0; i < 5; i++)
            {
                WriteBig(codeDirectory, 0);       // nSpecialSlots .. teamOffset padding to 44
            }

            codeDirectory.Write(identifier, 0, identifier.Length);

            var entitlements = new MemoryStream();
            WriteBig(entitlements, 0xfade7171);
            WriteBig(entitlements, (uint)(8 + plist.Length));
            entitlements.Write(plist, 0, plist.Length);

            var indexSize = 12 + (2 * 8);
            var cdOffset = indexSize;
            var entOffset = cdOffset + (int)codeDirectory.Length;

            var blob = new MemoryStream();
            WriteBig(blob, corrupt ? 0xdeadbeef : 0xfade0cc0);
            WriteBig(blob, (uint)(entOffset + entitlements.Length));
            WriteBig(blob, 2);                    // count
            WriteBig(blob, 0); WriteBig(blob, (uint)cdOffset);   // slot 0
            WriteBig(blob, 5); WriteBig(blob, (uint)entOffset);  // slot 5
            codeDirectory.WriteTo(blob);
            entitlements.WriteTo(blob);
            return blob.ToArray();
        }

        private static byte[] WrapFat(byte[] thin, int arm64Offset)
        {
            var fat = new byte[arm64Offset + thin.Length];
            using (var stream = new MemoryStream(fat))
            {
                WriteBig(stream, 0xcafebabe);
                WriteBig(stream, 2);              // two architectures
                // x86_64 slice first, at a bogus offset, so the reader has to
                // pick the arm64 one rather than the first one.
                WriteBig(stream, 0x01000007); WriteBig(stream, 3);
                WriteBig(stream, 0x1000); WriteBig(stream, 16); WriteBig(stream, 14);
                WriteBig(stream, 0x0100000c); WriteBig(stream, 0);
                WriteBig(stream, (uint)arm64Offset); WriteBig(stream, (uint)thin.Length); WriteBig(stream, 14);
            }

            Buffer.BlockCopy(thin, 0, fat, arm64Offset, thin.Length);
            return fat;
        }

        private static byte[] FixedName(string name)
        {
            var bytes = new byte[16];
            Encoding.ASCII.GetBytes(name, 0, name.Length, bytes, 0);
            return bytes;
        }

        private static void WriteBig(Stream stream, uint value)
        {
            stream.WriteByte((byte)(value >> 24));
            stream.WriteByte((byte)(value >> 16));
            stream.WriteByte((byte)(value >> 8));
            stream.WriteByte((byte)value);
        }
    }
}
