using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>
    /// Builds the per-request proof of possession that every protected call
    /// carries.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three headers travel with each protected request:
    /// <c>Authorization: Bearer &lt;token&gt;</c>,
    /// <c>X-Access-Proof: base64url(utf8(proofJson))</c> and
    /// <c>X-Access-Signature: base64url(DER ECDSA-SHA256 over those utf8 proof
    /// bytes)</c>, both unpadded.
    /// </para>
    /// <para>
    /// The signature covers the proof bytes exactly as transmitted. The server
    /// base64url-decodes the header, verifies the signature over those bytes and
    /// only then parses them as JSON. That ordering is what frees the Dart, .NET
    /// and Python clients from needing byte-identical JSON serialisation — there
    /// is no RFC 8785 canonicalisation anywhere in this protocol, and adding
    /// server-side re-serialisation before verification would break every SDK
    /// that does not serialise exactly like the reference one.
    /// </para>
    /// <para>
    /// The nonce is 32 random bytes and is single-use: the server commits it only
    /// after the signature verifies, so a rejected request cannot burn a nonce,
    /// and a captured proof replayed verbatim fails with
    /// <c>access_proof_replay</c>.
    /// </para>
    /// </remarks>
    public static class AccessProof
    {
        /// <summary>The proof schema version this SDK emits and the server accepts.</summary>
        public const int Version = 1;

        /// <summary>The number of random bytes in a nonce. The server rejects any other length.</summary>
        public const int NonceByteLength = 32;

        /// <summary>
        /// Serialises the proof JSON for a request.
        /// </summary>
        /// <remarks>
        /// The fields are written in the same order the Dart reference client
        /// uses. Order carries no meaning — the server verifies the signature
        /// over the received bytes before parsing — but keeping it identical
        /// makes captured traffic from the two SDKs directly comparable.
        /// </remarks>
        public static byte[] Serialize(
            string accessTokenSha256Hex,
            string bodySha256Hex,
            string installationId,
            string method,
            string nonce,
            string path,
            long timestamp)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
            {
                writer.WriteStartObject();
                writer.WriteString("access_token_sha256", accessTokenSha256Hex);
                writer.WriteString("body_sha256", bodySha256Hex);
                writer.WriteString("installation_id", installationId);
                writer.WriteString("method", method);
                writer.WriteString("nonce", nonce);
                writer.WriteString("path", path);
                writer.WriteNumber("timestamp", timestamp);
                writer.WriteNumber("version", Version);
                writer.WriteEndObject();
            }

            return buffer.ToArray();
        }

        /// <summary>Generates a fresh 32-byte nonce, base64url encoded without padding.</summary>
        public static string CreateNonce()
        {
            var bytes = new byte[NonceByteLength];
#if NET8_0_OR_GREATER
            RandomNumberGenerator.Fill(bytes);
#else
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(bytes);
            }
#endif
            return Base64Url.Encode(bytes);
        }

        /// <summary>Returns the current Unix time in seconds.</summary>
        public static long CurrentTimestamp()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>
        /// Hashes the body bytes exactly as the server will hash the bytes it
        /// receives. A GET carries no body and hashes the empty string.
        /// </summary>
        public static string BodyHash(byte[]? body)
        {
            return Hex.Sha256Hex(body ?? Array.Empty<byte>());
        }
    }
}
