using System;
using System.Collections.Generic;
using System.Text.Json;

namespace DeviceTrust.Client.Internal
{
    /// <summary>
    /// The one place JSON options are configured, so every request body and every
    /// signed payload is produced by the same serializer settings.
    /// </summary>
    public static class Json
    {
        /// <summary>
        /// Serializes a request body to the exact UTF-8 bytes that will be
        /// transmitted.
        /// </summary>
        /// <remarks>
        /// Written explicitly rather than through
        /// <c>JsonSerializer.Serialize&lt;T&gt;</c>, which is not trim-safe and
        /// would stop the SDK building inside an AOT-compiled Android
        /// application. See <see cref="JsonValueWriter"/>.
        /// </remarks>
        public static byte[] SerializeToUtf8Bytes(IReadOnlyDictionary<string, object?> value)
        {
            using var buffer = new System.IO.MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
            {
                JsonValueWriter.WriteObject(writer, value);
            }

            return buffer.ToArray();
        }

        /// <summary>Reads a string property, or null when it is missing or not a string.</summary>
        public static string? GetString(JsonElement element, string name)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        /// <summary>Reads a string property and throws when it is absent.</summary>
        public static string RequireString(JsonElement element, string name)
        {
            var value = GetString(element, name);
            if (string.IsNullOrEmpty(value))
            {
                throw new DeviceTrustProtocolException(
                    "The server response is missing the '" + name + "' field.",
                    "malformed_server_response");
            }

            return value!;
        }

        /// <summary>Reads an integer property, falling back to the supplied default.</summary>
        public static int GetInt32(JsonElement element, string name, int fallback = 0)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return fallback;
            }

            return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
                   && value.TryGetInt32(out var parsed)
                ? parsed
                : fallback;
        }

        /// <summary>Reads a boolean property, falling back to the supplied default.</summary>
        public static bool GetBoolean(JsonElement element, string name, bool fallback = false)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return fallback;
            }

            if (!element.TryGetProperty(name, out var value))
            {
                return fallback;
            }

            return value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => fallback,
            };
        }

        /// <summary>Reads an object property, or null when it is missing or not an object.</summary>
        public static JsonElement? GetObject(JsonElement element, string name)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Object
                ? value
                : (JsonElement?)null;
        }

        /// <summary>Reads an array of strings, returning an empty list when absent.</summary>
        public static IReadOnlyList<string> GetStringArray(JsonElement element, string name)
        {
            if (element.ValueKind != JsonValueKind.Object
                || !element.TryGetProperty(name, out var value)
                || value.ValueKind != JsonValueKind.Array)
            {
                return Array.Empty<string>();
            }

            var items = new List<string>();
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var text = item.GetString();
                    if (text is not null)
                    {
                        items.Add(text);
                    }
                }
            }

            return items;
        }

        /// <summary>Converts a JSON object into a plain dictionary for callers that want loose access.</summary>
        public static IReadOnlyDictionary<string, JsonElement> ToDictionary(JsonElement element)
        {
            var map = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            if (element.ValueKind != JsonValueKind.Object)
            {
                return map;
            }

            foreach (var property in element.EnumerateObject())
            {
                map[property.Name] = property.Value;
            }

            return map;
        }
    }
}
