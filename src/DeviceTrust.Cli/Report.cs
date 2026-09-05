using System;
using System.Collections.Generic;
using System.Globalization;

namespace DeviceTrust.Cli
{
    /// <summary>Console output helpers shared by every command.</summary>
    public static class Report
    {
        /// <summary>Prints a section heading.</summary>
        public static void Heading(string text)
        {
            Console.WriteLine();
            Console.WriteLine(text);
            Console.WriteLine(new string('-', Math.Min(text.Length, 78)));
        }

        /// <summary>Prints an aligned label/value pair.</summary>
        public static void Field(string label, string? value)
        {
            Console.WriteLine("  {0,-30} {1}", label, string.IsNullOrEmpty(value) ? "-" : value);
        }

        /// <summary>Prints an aligned label/value pair for a number.</summary>
        public static void Field(string label, int value)
        {
            Field(label, value.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>Prints a bullet line.</summary>
        public static void Line(string text)
        {
            Console.WriteLine("  " + text);
        }

        /// <summary>Prints a warning to standard error without colour codes, so logs stay readable.</summary>
        public static void Warn(string text)
        {
            Console.Error.WriteLine("WARNING  " + text);
        }

        /// <summary>Prints a test outcome line in the same shape the Python suite uses.</summary>
        public static void Outcome(string status, string name, string? detail = null)
        {
            Console.WriteLine("{0} {1}", status.PadRight(4), name);
            if (!string.IsNullOrEmpty(detail))
            {
                foreach (var line in detail!.Split('\n'))
                {
                    Console.WriteLine("       " + line.TrimEnd());
                }
            }
        }

        /// <summary>Prints the final tally.</summary>
        public static void Tally(int passed, int failed, int skipped)
        {
            Console.WriteLine();
            Console.WriteLine(
                "{0} passed, {1} failed, {2} skipped",
                passed.ToString(CultureInfo.InvariantCulture),
                failed.ToString(CultureInfo.InvariantCulture),
                skipped.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>Renders a list as a comma-separated string.</summary>
        public static string Join(IReadOnlyCollection<string> values)
        {
            return values.Count == 0 ? "-" : string.Join(", ", values);
        }
    }
}
