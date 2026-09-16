using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// Reads the XML property list Apple embeds as an app's entitlements.
    /// </summary>
    /// <remarks>
    /// Deliberately small. It understands the value types entitlements actually
    /// use — string, boolean, integer, real, array and nested dictionary — and
    /// returns plain .NET values. The parser refuses DTD processing and external
    /// entities, because the bytes come out of a binary the app did not write.
    /// </remarks>
    public static class EntitlementsPlist
    {
        /// <summary>Parses an XML plist into a dictionary, or returns null when it is not one.</summary>
        public static IReadOnlyDictionary<string, object?>? TryParse(byte[] plist)
        {
            if (plist is null || plist.Length == 0)
            {
                return null;
            }

            XDocument document;
            try
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Ignore,
                    XmlResolver = null,
                    IgnoreComments = true,
                    IgnoreProcessingInstructions = true,
                };

                using var stream = new MemoryStream(plist);
                using var reader = XmlReader.Create(stream, settings);
                document = XDocument.Load(reader);
            }
            catch (XmlException)
            {
                return null;
            }

            var root = document.Root;
            if (root is null || root.Name.LocalName != "plist")
            {
                return null;
            }

            var dictionary = root.Elements().FirstOrDefault(element => element.Name.LocalName == "dict");
            return dictionary is null ? null : ReadDictionary(dictionary);
        }

        /// <summary>Formats entitlements for logging, one per line.</summary>
        public static string Describe(IReadOnlyDictionary<string, object?> entitlements)
        {
            if (entitlements is null)
            {
                throw new ArgumentNullException(nameof(entitlements));
            }

            var builder = new StringBuilder();
            foreach (var entry in entitlements)
            {
                builder.Append(entry.Key).Append(" = ").Append(Render(entry.Value)).AppendLine();
            }

            return builder.ToString();
        }

        private static Dictionary<string, object?> ReadDictionary(XElement dictionary)
        {
            // A plist dict is a flat sequence of <key>name</key><value/> pairs.
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            string? pendingKey = null;
            foreach (var child in dictionary.Elements())
            {
                if (child.Name.LocalName == "key")
                {
                    pendingKey = child.Value;
                    continue;
                }

                if (pendingKey is not null)
                {
                    result[pendingKey] = ReadValue(child);
                    pendingKey = null;
                }
            }

            return result;
        }

        private static object? ReadValue(XElement element)
        {
            switch (element.Name.LocalName)
            {
                case "string":
                case "date":
                case "data":
                    return element.Value;
                case "integer":
                    return long.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
                        ? number
                        : (object)element.Value;
                case "real":
                    return double.TryParse(element.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var real)
                        ? real
                        : (object)element.Value;
                case "true":
                    return true;
                case "false":
                    return false;
                case "array":
                    return element.Elements().Select(ReadValue).ToList();
                case "dict":
                    return ReadDictionary(element);
                default:
                    return element.ToString();
            }
        }

        private static string Render(object? value)
        {
            return value switch
            {
                null => "<null>",
                IEnumerable<object?> list => "[" + string.Join(", ", list.Select(Render)) + "]",
                IReadOnlyDictionary<string, object?> map => "{" + string.Join(", ", map.Select(p => p.Key + "=" + Render(p.Value))) + "}",
                _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty,
            };
        }
    }
}
