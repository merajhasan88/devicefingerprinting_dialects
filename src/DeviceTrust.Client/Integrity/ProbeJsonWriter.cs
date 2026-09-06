using System;
using System.Collections.Generic;
using System.Text.Json;
using DeviceTrust.Client.Internal;

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
            JsonValueWriter.WriteValue(writer, value);
        }
    }
}
