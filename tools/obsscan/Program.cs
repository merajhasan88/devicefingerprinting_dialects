using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

// Finds every API this app calls that Apple has obsoleted on a given iOS
// version, by reading the reference assembly's own metadata.
//
// Why not an analyser: CA1422 only runs when the project has a platform target
// framework, and the iOS sources are compile-checked on Linux for plain net9.0,
// where the platform analysers are inert. This asks the same question of the
// same metadata without needing the workload.
//
// usage: obsscan <Microsoft.iOS.dll> <ios-version-prefix> <source dir> ...
internal static class Program
{
    private static int Main(string[] args)
    {
        var refDll = args[0];
        var versionPrefix = args[1];
        var sources = args.Skip(2).ToArray();

        var dir = Path.GetDirectoryName(Path.GetFullPath(refDll))!;
        var paths = new List<string>(Directory.GetFiles(dir, "*.dll"));
        var runtime = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        paths.AddRange(Directory.GetFiles(runtime, "*.dll"));

        using var context = new MetadataLoadContext(new PathAssemblyResolver(paths));
        var assembly = context.LoadFromAssemblyPath(Path.GetFullPath(refDll));

        // member simple name -> the qualified names it could refer to
        var obsoleted = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        void Note(string simple, string qualified)
        {
            if (!obsoleted.TryGetValue(simple, out var set))
            {
                obsoleted[simple] = set = new SortedSet<string>(StringComparer.Ordinal);
            }

            set.Add(qualified);
        }

        static bool IsObsoletedOn(IEnumerable<CustomAttributeData> attributes, string prefix)
        {
            foreach (var attribute in attributes)
            {
                if (attribute.AttributeType.Name != "ObsoletedOSPlatformAttribute")
                {
                    continue;
                }

                var argument = attribute.ConstructorArguments.Count > 0
                    ? attribute.ConstructorArguments[0].Value as string
                    : null;
                if (argument is not null &&
                    argument.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        foreach (var type in assembly.GetExportedTypes())
        {
            if (IsObsoletedOn(type.GetCustomAttributesData(), versionPrefix))
            {
                Note(type.Name, type.FullName + " (whole type)");
            }

            const BindingFlags Flags = BindingFlags.Public | BindingFlags.Instance |
                                       BindingFlags.Static | BindingFlags.DeclaredOnly;
            foreach (var member in type.GetMembers(Flags))
            {
                if (!IsObsoletedOn(member.GetCustomAttributesData(), versionPrefix))
                {
                    continue;
                }

                // A constructor is written as `new Type(`, so index it by the
                // type's name rather than by ".ctor", which appears in no source.
                var simple = member is ConstructorInfo ? type.Name : member.Name;
                Note(simple, type.FullName + "." + member.Name);
            }
        }

        Console.WriteLine($"reference assembly declares {obsoleted.Count} distinct names obsoleted on {versionPrefix}*");

        var identifier = new Regex(@"[A-Za-z_][A-Za-z0-9_]*", RegexOptions.Compiled);
        var hits = 0;
        var settled = 0;
        foreach (var source in sources)
        {
            var files = Directory.Exists(source)
                ? Directory.GetFiles(source, "*.cs", SearchOption.AllDirectories)
                : new[] { source };
            foreach (var file in files)
            {
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    if (line.TrimStart().StartsWith("//", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    foreach (Match match in identifier.Matches(line))
                    {
                        if (!obsoleted.TryGetValue(match.Value, out var qualified))
                        {
                            continue;
                        }

                        // `new UIWindow(` is a constructor call; a bare mention
                        // of the type name is not.
                        var isTypeName = qualified.Any(q => q.EndsWith(".ctor", StringComparison.Ordinal)
                                                            || q.EndsWith("(whole type)", StringComparison.Ordinal));
                        if (isTypeName && !line.Contains("new " + match.Value, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        // A call site with a pragma over it has already been
                        // argued about in writing; report it as settled rather
                        // than raising it again on every run.
                        var suppressed = false;
                        for (var back = Math.Max(0, i - 3); back < i; back++)
                        {
                            if (lines[back].Contains("#pragma warning disable CA1422", StringComparison.Ordinal))
                            {
                                suppressed = true;
                            }
                        }

                        if (suppressed)
                        {
                            settled++;
                            continue;
                        }

                        hits++;
                        Console.WriteLine($"{Path.GetFileName(file)}:{i + 1}: {match.Value}  ->  {string.Join(", ", qualified)}");
                        Console.WriteLine($"    {line.Trim()}");
                    }
                }
            }
        }

        Console.WriteLine(hits == 0
            ? $"no call sites to review ({settled} already suppressed in source)"
            : $"{hits} call site(s) to review, {settled} already suppressed");
        return 0;
    }
}
