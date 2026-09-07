using System;
using System.Collections.Generic;
using System.Globalization;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>One line of <c>/proc/self/maps</c>.</summary>
    public readonly struct ProcMapsEntry
    {
        /// <summary>Creates an entry.</summary>
        public ProcMapsEntry(ulong start, ulong end, string permissions, long offset, string inode, string path)
        {
            Start = start;
            End = end;
            Permissions = permissions;
            Offset = offset;
            Inode = inode;
            Path = path;
        }

        /// <summary>First address of the mapping.</summary>
        public ulong Start { get; }

        /// <summary>Address one past the end of the mapping.</summary>
        public ulong End { get; }

        /// <summary>The four permission characters, for example <c>r-xp</c>.</summary>
        public string Permissions { get; }

        /// <summary>Offset into the backing file.</summary>
        public long Offset { get; }

        /// <summary>The inode field, <c>0</c> for an anonymous mapping.</summary>
        public string Inode { get; }

        /// <summary>The pathname field, empty for an unlabelled anonymous mapping.</summary>
        public string Path { get; }

        /// <summary>Size of the mapping in bytes.</summary>
        public long Length => End > Start ? (long)(End - Start) : 0;

        /// <summary>Whether the pages may be read.</summary>
        public bool Readable => Permissions.Length > 0 && Permissions[0] == 'r';

        /// <summary>Whether the pages may be written.</summary>
        public bool Writable => Permissions.Length > 1 && Permissions[1] == 'w';

        /// <summary>Whether the pages may be executed.</summary>
        public bool Executable => Permissions.Length > 2 && Permissions[2] == 'x';

        /// <summary>
        /// Whether the mapping is anonymous and carries no name at all.
        /// </summary>
        /// <remarks>
        /// This is the shape Mono's code manager and an injected trampoline both
        /// have. Android lets a process name an anonymous mapping through
        /// <c>PR_SET_VMA_ANON_NAME</c>, which appears as <c>[anon:…]</c>; ART
        /// labels its regions that way, so an unlabelled one is the more
        /// interesting case.
        /// </remarks>
        public bool IsUnlabelledAnonymous => Path.Length == 0 && Inode == "0";

        /// <summary>Whether the mapping is anonymous but carries an <c>[anon:…]</c> label.</summary>
        public bool IsLabelledAnonymous => Path.StartsWith("[anon:", StringComparison.Ordinal);
    }

    /// <summary>
    /// Parses <c>/proc/self/maps</c>.
    /// </summary>
    /// <remarks>
    /// Lives in the platform-neutral package on purpose. The format is plain
    /// Linux rather than anything Android-specific, and the subtleties that have
    /// actually caused defects here — execute-only mappings, a JIT cache mapped
    /// several times over one memfd, deleted backing files — are worth having
    /// under unit test rather than only exercised on a handset.
    /// </remarks>
    public static class ProcMapsParser
    {
        /// <summary>Parses one line, returning false for anything malformed.</summary>
        public static bool TryParse(string line, out ProcMapsEntry entry)
        {
            entry = default;
            if (string.IsNullOrWhiteSpace(line))
            {
                return false;
            }

            // address perms offset dev inode [pathname]; the pathname may itself
            // contain spaces, as "(deleted)" suffixes do, so the split is capped.
            var parts = line.Split(new[] { ' ', '\t' }, 6, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5)
            {
                return false;
            }

            var bounds = parts[0].Split('-');
            if (bounds.Length != 2
                || !ulong.TryParse(bounds[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var start)
                || !ulong.TryParse(bounds[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var end)
                || !long.TryParse(parts[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
            {
                return false;
            }

            entry = new ProcMapsEntry(
                start,
                end,
                parts[1],
                offset,
                parts[4],
                parts.Length >= 6 ? parts[5].Trim() : string.Empty);
            return true;
        }

        /// <summary>Parses every well-formed line.</summary>
        public static IReadOnlyList<ProcMapsEntry> ParseAll(IEnumerable<string> lines)
        {
            if (lines is null)
            {
                throw new ArgumentNullException(nameof(lines));
            }

            var entries = new List<ProcMapsEntry>();
            foreach (var line in lines)
            {
                if (TryParse(line, out var entry))
                {
                    entries.Add(entry);
                }
            }

            return entries;
        }
    }
}
