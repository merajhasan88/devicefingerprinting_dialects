using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// Writes probe measurements into the signed report.
    /// </summary>
    /// <remarks>
    /// Probe values are loosely typed on purpose: a collector reports whatever
    /// the platform gave it — a string, a count, a flag, a list of paths, a map
    /// of system properties — and the server scores those raw shapes. Writing
    /// them explicitly rather than through reflection keeps the report's JSON
    /// types predictable, which matters because the server distinguishes an
    /// integer <c>tracer_pid</c> from a string one and treats a non-boolean
    /// where it wants a boolean as simply "not true".
    /// </remarks>
    public static class ProbeJsonWriter
    {
        /// <summary>Writes the <c>probe_results</c> object.</summary>
        public static void WriteProbes(Utf8JsonWriter writer, IReadOnlyDictionary<string, ProbeResult> probes)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (probes is null)
            {
                throw new ArgumentNullException(nameof(probes));
            }

            writer.WriteStartObject();
            foreach (var probe in probes)
            {
                writer.WritePropertyName(probe.Key);
                writer.WriteStartObject();
                foreach (var field in probe.Value.Fields)
                {
                    writer.WritePropertyName(field.Key);
                    WriteValue(writer, field.Value);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        /// <summary>Writes one loosely typed measurement value.</summary>
        public static void WriteValue(Utf8JsonWriter writer, object? value)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            switch (value)
            {
                case null:
                    writer.WriteNullValue();
                    break;
                case string text:
                    writer.WriteStringValue(text);
                    break;
                case bool flag:
                    writer.WriteBooleanValue(flag);
                    break;
                case int number:
                    writer.WriteNumberValue(number);
                    break;
                case long number:
                    writer.WriteNumberValue(number);
                    break;
                case double number:
                    writer.WriteNumberValue(number);
                    break;
                case IReadOnlyDictionary<string, string> map:
                    writer.WriteStartObject();
                    foreach (var entry in map)
                    {
                        writer.WriteString(entry.Key, entry.Value);
                    }

                    writer.WriteEndObject();
                    break;
                case IReadOnlyDictionary<string, object?> map:
                    writer.WriteStartObject();
                    foreach (var entry in map)
                    {
                        writer.WritePropertyName(entry.Key);
                        WriteValue(writer, entry.Value);
                    }

                    writer.WriteEndObject();
                    break;
                case IEnumerable sequence:
                    writer.WriteStartArray();
                    foreach (var item in sequence)
                    {
                        WriteValue(writer, item);
                    }

                    writer.WriteEndArray();
                    break;
                default:
                    writer.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                    break;
            }
        }
    }
}
