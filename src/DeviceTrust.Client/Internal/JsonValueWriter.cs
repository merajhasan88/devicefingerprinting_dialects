using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace DeviceTrust.Client.Internal
{
    /// <summary>
    /// Writes loosely typed values with an explicit <see cref="Utf8JsonWriter"/>
    /// rather than through reflection-based serialization.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two reasons, and the second one is the important one.
    /// </para>
    /// <para>
    /// It keeps the SDK usable in a trimmed or AOT-compiled application.
    /// <c>JsonSerializer.Serialize&lt;T&gt;</c> carries
    /// <c>RequiresUnreferencedCode</c>, so an Android app built with
    /// <c>PublishTrimmed</c> — which .NET requires for
    /// <c>RunAOTCompilation</c> — fails to build against a library that uses it.
    /// That matters here beyond convenience: on Android the Mono JIT maps
    /// writable-and-executable memory, which the server scores as
    /// <c>android_wx_memory +60</c>, so AOT is how a .NET client reaches the same
    /// clean baseline a Flutter client does.
    /// </para>
    /// <para>
    /// It also makes the transmitted bytes explicit. The access proof commits to
    /// the SHA-256 of the exact request body, so a serializer whose output could
    /// shift with a runtime version, a trimming decision or a property-ordering
    /// change is a liability that would surface as
    /// <c>access_proof_body_mismatch</c>.
    /// </para>
    /// </remarks>
    public static class JsonValueWriter
    {
        /// <summary>Writes one loosely typed value.</summary>
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
                case decimal number:
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
                    WriteObject(writer, map);
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

        /// <summary>Writes a JSON object from a dictionary.</summary>
        public static void WriteObject(Utf8JsonWriter writer, IReadOnlyDictionary<string, object?> value)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            writer.WriteStartObject();
            foreach (var entry in value)
            {
                writer.WritePropertyName(entry.Key);
                WriteValue(writer, entry.Value);
            }

            writer.WriteEndObject();
        }
    }
}
