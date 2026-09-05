using System;

namespace DeviceTrust.Client.Internal
{
    /// <summary>
    /// Unpadded base64url, the only encoding this protocol puts on the wire.
    /// </summary>
    /// <remarks>
    /// The server decodes every one of these values with a decoder that re-adds
    /// the padding itself, and it rejects a value whose decoded length is wrong
    /// (for example a 32-byte access-proof nonce). Emitting the '=' padding that
    /// <see cref="Convert.ToBase64String(byte[])"/> produces would therefore
    /// change the transmitted bytes for no benefit, so every encode here strips
    /// it and every decode restores it.
    /// </remarks>
    public static class Base64Url
    {
        /// <summary>Encodes bytes as base64url with no padding.</summary>
        public static string Encode(byte[] value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return Convert.ToBase64String(value)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        /// <summary>Encodes a span as base64url with no padding.</summary>
        public static string Encode(ReadOnlySpan<byte> value)
        {
            return Encode(value.ToArray());
        }

        /// <summary>Decodes unpadded or padded base64url text.</summary>
        public static byte[] Decode(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var normalized = value.Replace('-', '+').Replace('_', '/');
            switch (normalized.Length % 4)
            {
                case 2:
                    normalized += "==";
                    break;
                case 3:
                    normalized += "=";
                    break;
                case 0:
                    break;
                default:
                    throw new FormatException("The base64url value has an invalid length.");
            }

            return Convert.FromBase64String(normalized);
        }
    }
}
