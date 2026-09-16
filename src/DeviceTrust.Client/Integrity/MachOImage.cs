using System;
using System.Collections.Generic;
using System.Text;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>A section inside a Mach-O segment, located by name.</summary>
    public readonly struct MachOSection
    {
        /// <summary>Creates a section descriptor.</summary>
        public MachOSection(ulong virtualAddress, long fileOffset, long size)
        {
            VirtualAddress = virtualAddress;
            FileOffset = fileOffset;
            Size = size;
        }

        /// <summary>The unslid virtual address the section is linked at.</summary>
        public ulong VirtualAddress { get; }

        /// <summary>Where the section's bytes live in the file, relative to the slice.</summary>
        public long FileOffset { get; }

        /// <summary>The section's size in bytes.</summary>
        public long Size { get; }
    }

    /// <summary>What the embedded code signature says about the binary it is attached to.</summary>
    public sealed class MachOCodeSignature
    {
        internal MachOCodeSignature()
        {
        }

        /// <summary>
        /// The CodeDirectory identifier: what the signer embedded, normally the
        /// bundle id. This is the value the server's <c>signing_identifier</c>
        /// field is a contract for.
        /// </summary>
        public string? Identifier { get; internal set; }

        /// <summary>The CodeDirectory flags word, when present.</summary>
        public uint? CodeDirectoryFlags { get; internal set; }

        /// <summary>The raw entitlements property list from slot 5, when present.</summary>
        public byte[]? EntitlementsPlist { get; internal set; }

        /// <summary>Why parsing stopped, if it did not complete.</summary>
        public string? ParseError { get; internal set; }
    }

    /// <summary>
    /// A byte-level reader for a 64-bit Mach-O image.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the platform-neutral part of the iOS collector, kept in the core
    /// package so it can be unit-tested on a Linux build machine against a
    /// synthetic image — the rest of the iOS folder can only be compiled on
    /// macOS, and a parser that has never run is a parser that has never been
    /// right.
    /// </para>
    /// <para>
    /// It exists because the obvious way to read an app's own signing identity
    /// — <c>SecTaskCopyValueForEntitlement</c> — is public API on macOS only. On
    /// iOS it is private, and the Swift reference client could not even compile
    /// against it. Reading the app's own executable is the better measurement
    /// regardless: it reports what is embedded in the file rather than what the
    /// kernel was told at launch, and it degrades honestly, because an unsigned
    /// build has no <c>LC_CODE_SIGNATURE</c> at all and is reported as unsigned
    /// instead of being mistaken for a clean signed app.
    /// </para>
    /// <para>
    /// Byte order is mixed and has to be respected exactly: the Mach-O header
    /// and load commands are little-endian on every device that matters, but a
    /// fat header and every field inside the code-signature blobs are
    /// <b>big-endian</b> regardless of host. Integers are assembled a byte at a
    /// time because the offsets are not guaranteed to be aligned.
    /// </para>
    /// </remarks>
    public sealed class MachOImage
    {
        private const uint MagicMh64 = 0xfeedfacf;
        private const uint MagicFat = 0xcafebabe;
        private const uint CpuTypeArm64 = 0x0100000c;
        private const uint LcSegment64 = 0x19;
        private const uint LcCodeSignature = 0x1d;
        private const uint MagicEmbeddedSignature = 0xfade0cc0;
        private const uint MagicCodeDirectory = 0xfade0c02;
        private const uint MagicEntitlements = 0xfade7171;
        private const int HeaderSize64 = 32;
        private const int SegmentCommandSize64 = 72;
        private const int SectionSize64 = 80;

        private readonly byte[] _file;

        private MachOImage(byte[] file, int sliceOffset)
        {
            _file = file;
            SliceOffset = sliceOffset;
        }

        /// <summary>Where the 64-bit slice begins: zero for a thin image, the arm64 slice for a fat one.</summary>
        public int SliceOffset { get; }

        /// <summary>
        /// Parses a thin 64-bit image, or the arm64 slice of a fat one. Returns
        /// null for anything else.
        /// </summary>
        /// <remarks>
        /// Only <c>MH_MAGIC_64</c> is accepted. A byte-swapped image would need
        /// every following field swapped too, and silently misparsing one is
        /// worse than reporting that the image was not recognised.
        /// </remarks>
        public static MachOImage? TryParse(byte[] file)
        {
            if (file is null || file.Length < HeaderSize64)
            {
                return null;
            }

            if (ReadLittle(file, 0) == MagicMh64)
            {
                return new MachOImage(file, 0);
            }

            if (ReadBig(file, 0) != MagicFat)
            {
                return null;
            }

            var count = ReadBig(file, 4);
            if (count is null || count > 64)
            {
                return null;
            }

            for (var index = 0; index < count; index++)
            {
                var entry = 8 + (index * 20);
                var cpu = ReadBig(file, entry);
                var offset = ReadBig(file, entry + 8);
                if (cpu == CpuTypeArm64 && offset is not null && offset < int.MaxValue
                    && ReadLittle(file, (int)offset) == MagicMh64)
                {
                    return new MachOImage(file, (int)offset);
                }
            }

            return null;
        }

        /// <summary>Finds a named section within a named segment, for example <c>__TEXT,__text</c>.</summary>
        public MachOSection? FindSection(string segment, string section)
        {
            if (segment is null)
            {
                throw new ArgumentNullException(nameof(segment));
            }

            if (section is null)
            {
                throw new ArgumentNullException(nameof(section));
            }

            var commandCount = ReadLittle(_file, SliceOffset + 16);
            if (commandCount is null)
            {
                return null;
            }

            var cursor = SliceOffset + HeaderSize64;
            for (var index = 0; index < commandCount; index++)
            {
                var command = ReadLittle(_file, cursor);
                var commandSize = ReadLittle(_file, cursor + 4);
                if (command is null || commandSize is null || commandSize < 8)
                {
                    return null;
                }

                if (command == LcSegment64
                    && string.Equals(ReadFixedName(cursor + 8), segment, StringComparison.Ordinal))
                {
                    var sectionCount = ReadLittle(_file, cursor + 64);
                    var entry = cursor + SegmentCommandSize64;
                    for (var sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++)
                    {
                        if (string.Equals(ReadFixedName(entry), section, StringComparison.Ordinal))
                        {
                            var address = ReadLittle64(_file, entry + 32);
                            var size = ReadLittle64(_file, entry + 40);
                            var fileOffset = ReadLittle(_file, entry + 48);
                            if (address is null || size is null || fileOffset is null)
                            {
                                return null;
                            }

                            return new MachOSection(address.Value, fileOffset.Value, (long)size.Value);
                        }

                        entry += SectionSize64;
                    }
                }

                cursor += (int)commandSize;
                if (cursor >= _file.Length)
                {
                    return null;
                }
            }

            return null;
        }

        /// <summary>
        /// Reads the embedded code signature, or returns null when the image
        /// carries no <c>LC_CODE_SIGNATURE</c> at all — which is what an
        /// unsigned build looks like, and must be reported as such.
        /// </summary>
        public MachOCodeSignature? ReadCodeSignature()
        {
            var commandCount = ReadLittle(_file, SliceOffset + 16);
            if (commandCount is null)
            {
                return null;
            }

            var cursor = SliceOffset + HeaderSize64;
            for (var index = 0; index < commandCount; index++)
            {
                var command = ReadLittle(_file, cursor);
                var commandSize = ReadLittle(_file, cursor + 4);
                if (command is null || commandSize is null || commandSize < 8)
                {
                    return null;
                }

                if (command == LcCodeSignature)
                {
                    var dataOffset = ReadLittle(_file, cursor + 8);
                    var dataSize = ReadLittle(_file, cursor + 12);
                    if (dataOffset is null || dataSize is null)
                    {
                        return null;
                    }

                    // dataoff is relative to the slice, so add the slice back
                    // for a fat image.
                    var absolute = (long)SliceOffset + dataOffset.Value;
                    if (absolute < 0 || absolute + dataSize.Value > _file.Length)
                    {
                        return new MachOCodeSignature { ParseError = "The signature blob lies outside the file." };
                    }

                    return ParseSuperBlob((int)absolute, (int)dataSize.Value);
                }

                cursor += (int)commandSize;
                if (cursor >= _file.Length)
                {
                    return null;
                }
            }

            return null;
        }

        private MachOCodeSignature ParseSuperBlob(int offset, int size)
        {
            var signature = new MachOCodeSignature();
            if (ReadBig(_file, offset) != MagicEmbeddedSignature)
            {
                signature.ParseError = "Not an embedded signature SuperBlob.";
                return signature;
            }

            var blobCount = ReadBig(_file, offset + 8);
            if (blobCount is null || blobCount > 128)
            {
                signature.ParseError = "Not an embedded signature SuperBlob.";
                return signature;
            }

            for (var index = 0; index < blobCount; index++)
            {
                var entry = offset + 12 + (index * 8);
                var slot = ReadBig(_file, entry);
                var relative = ReadBig(_file, entry + 4);
                if (slot is null || relative is null)
                {
                    return signature;
                }

                var blob = offset + (int)relative.Value;
                if (blob + 8 > offset + size)
                {
                    continue;
                }

                switch (slot.Value)
                {
                    case 0: // CSSLOT_CODEDIRECTORY
                        if (ReadBig(_file, blob) != MagicCodeDirectory)
                        {
                            continue;
                        }

                        signature.CodeDirectoryFlags = ReadBig(_file, blob + 12);
                        var identOffset = ReadBig(_file, blob + 20);
                        if (identOffset is null)
                        {
                            continue;
                        }

                        var start = blob + (int)identOffset.Value;
                        var end = start;
                        while (end < _file.Length && _file[end] != 0)
                        {
                            end++;
                        }

                        if (end > start)
                        {
                            signature.Identifier = Encoding.UTF8.GetString(_file, start, end - start);
                        }

                        break;

                    case 5: // CSSLOT_ENTITLEMENTS
                        if (ReadBig(_file, blob) != MagicEntitlements)
                        {
                            continue;
                        }

                        var length = ReadBig(_file, blob + 4);
                        if (length is null || length <= 8)
                        {
                            continue;
                        }

                        var plistStart = blob + 8;
                        var plistEnd = blob + (int)length.Value;
                        if (plistEnd > _file.Length || plistStart >= plistEnd)
                        {
                            continue;
                        }

                        var plist = new byte[plistEnd - plistStart];
                        Buffer.BlockCopy(_file, plistStart, plist, 0, plist.Length);
                        signature.EntitlementsPlist = plist;
                        break;

                    default:
                        continue;
                }
            }

            return signature;
        }

        // Mach-O stores segment and section names in a fixed 16-byte field that
        // is NOT necessarily NUL-terminated.
        private string ReadFixedName(int offset)
        {
            if (offset < 0 || offset + 16 > _file.Length)
            {
                return string.Empty;
            }

            var length = 0;
            while (length < 16 && _file[offset + length] != 0)
            {
                length++;
            }

            return Encoding.ASCII.GetString(_file, offset, length);
        }

        private static uint? ReadLittle(byte[] data, int offset)
        {
            if (offset < 0 || offset + 4 > data.Length)
            {
                return null;
            }

            return data[offset]
                   | ((uint)data[offset + 1] << 8)
                   | ((uint)data[offset + 2] << 16)
                   | ((uint)data[offset + 3] << 24);
        }

        private static ulong? ReadLittle64(byte[] data, int offset)
        {
            var low = ReadLittle(data, offset);
            var high = ReadLittle(data, offset + 4);
            return low is null || high is null ? null : low.Value | ((ulong)high.Value << 32);
        }

        private static uint? ReadBig(byte[] data, int offset)
        {
            if (offset < 0 || offset + 4 > data.Length)
            {
                return null;
            }

            return ((uint)data[offset] << 24)
                   | ((uint)data[offset + 1] << 16)
                   | ((uint)data[offset + 2] << 8)
                   | data[offset + 3];
        }
    }
}
