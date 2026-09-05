using System;
using System.Security.Cryptography;
using System.Text;

namespace DeviceTrust.Client.Internal
{
    /// <summary>
    /// Lowercase hex digests. The protocol carries every SHA-256 digest as hex,
    /// not base64url, and the server compares them with a constant-time equal on
    /// the exact string, so the case must be lowercase.
    /// </summary>
    public static class Hex
    {
        /// <summary>Formats bytes as lowercase hexadecimal.</summary>
        public static string Encode(byte[] value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            var builder = new StringBuilder(value.Length * 2);
            foreach (var item in value)
            {
                builder.Append(item.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }

        /// <summary>Returns the lowercase hex SHA-256 digest of the given bytes.</summary>
        public static string Sha256Hex(byte[] value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            using var sha256 = SHA256.Create();
            return Encode(sha256.ComputeHash(value));
        }

        /// <summary>Returns the lowercase hex SHA-256 digest of the UTF-8 bytes of the given text.</summary>
        public static string Sha256Hex(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            return Sha256Hex(Encoding.UTF8.GetBytes(value));
        }
    }
}
