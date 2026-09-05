using System;
using System.Text;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// The public half of the installation key, as the server expects it: an EC
    /// P-256 JWK restricted to ES256.
    /// </summary>
    /// <remarks>
    /// The server's authoritative identity for an installation is the RFC 7638
    /// thumbprint of this key, not the client-chosen UUID. That is what lets a
    /// device be recognised after the UUID is lost but the OS keystore entry
    /// survives, and it is why <see cref="Thumbprint"/> must be computed over
    /// the canonical member order below and nothing else.
    /// </remarks>
    public sealed class EcPublicJsonWebKey
    {
        /// <summary>Creates a P-256 public JWK from raw 32-byte coordinates.</summary>
        public EcPublicJsonWebKey(byte[] x, byte[] y)
        {
            if (x is null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if (y is null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            if (x.Length != 32 || y.Length != 32)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "P-256 coordinates must be exactly 32 bytes each; the server rejects anything else.");
            }

            X = Base64Url.Encode(x);
            Y = Base64Url.Encode(y);
        }

        /// <summary>Creates a P-256 public JWK from already-encoded coordinates.</summary>
        public EcPublicJsonWebKey(string x, string y)
        {
            X = x ?? throw new ArgumentNullException(nameof(x));
            Y = y ?? throw new ArgumentNullException(nameof(y));
        }

        /// <summary>Always <c>EC</c>.</summary>
        public string Kty => "EC";

        /// <summary>Always <c>P-256</c>.</summary>
        public string Crv => "P-256";

        /// <summary>Always <c>ES256</c>.</summary>
        public string Alg => "ES256";

        /// <summary>The base64url X coordinate.</summary>
        public string X { get; }

        /// <summary>The base64url Y coordinate.</summary>
        public string Y { get; }

        /// <summary>
        /// The RFC 7638 thumbprint, lowercase hex SHA-256 over the canonical
        /// members in lexicographic order: <c>crv</c>, <c>kty</c>, <c>x</c>,
        /// <c>y</c>. The server computes exactly this and stores it as the unique
        /// installation identity.
        /// </summary>
        public string Thumbprint
        {
            get
            {
                var canonical = "{\"crv\":\"" + Crv + "\",\"kty\":\"" + Kty
                                + "\",\"x\":\"" + X + "\",\"y\":\"" + Y + "\"}";
                return Hex.Sha256Hex(Encoding.UTF8.GetBytes(canonical));
            }
        }

        /// <summary>Writes the JWK exactly as the registration body needs it.</summary>
        public void Write(Utf8JsonWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteStartObject();
            writer.WriteString("kty", Kty);
            writer.WriteString("crv", Crv);
            writer.WriteString("alg", Alg);
            writer.WriteString("x", X);
            writer.WriteString("y", Y);
            writer.WriteEndObject();
        }

        /// <summary>Parses a JWK from a JSON object, validating the fields the server insists on.</summary>
        public static EcPublicJsonWebKey Parse(JsonElement element)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The key store did not return a public key object.");
            }

            var kty = Json.GetString(element, "kty");
            var crv = Json.GetString(element, "crv");
            var alg = Json.GetString(element, "alg");
            var x = Json.GetString(element, "x");
            var y = Json.GetString(element, "y");

            if (kty != "EC" || crv != "P-256" || alg != "ES256"
                || string.IsNullOrEmpty(x) || string.IsNullOrEmpty(y))
            {
                throw new InstallationKeyException(
                    "INVALID_PUBLIC_KEY",
                    "The key store did not return an EC P-256 ES256 public JWK.");
            }

            return new EcPublicJsonWebKey(x!, y!);
        }
    }
}
