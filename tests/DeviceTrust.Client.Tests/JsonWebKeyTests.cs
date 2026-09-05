using System;
using System.Linq;
using System.Text.Json;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Tests for the public JWK and its RFC 7638 thumbprint.
    /// </summary>
    /// <remarks>
    /// The thumbprint is the server's authoritative identity for an installation,
    /// so a client that computes it differently from the server enrols as a new
    /// device on every launch and never recognises a reinstall. The expected
    /// digest below was computed independently, outside this codebase, with the
    /// same canonical form the server uses:
    /// <c>json.dumps({"crv","kty","x","y"}, sort_keys=True, separators=(",",":"))</c>
    /// hashed with SHA-256.
    /// </remarks>
    public sealed class JsonWebKeyTests
    {
        private const string TestX = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
        private const string TestY = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0A";
        private const string ExpectedThumbprint =
            "b75648f2d3adefb299f587a961c522aada9772921822730986415be9c6ac005a";

        [Fact]
        public void Thumbprint_MatchesTheIndependentlyComputedVector()
        {
            var key = new EcPublicJsonWebKey(TestX, TestY);

            Assert.Equal(ExpectedThumbprint, key.Thumbprint);
        }

        [Fact]
        public void Thumbprint_IgnoresTheAlgorithmAndAnyOtherMember()
        {
            // RFC 7638 hashes only crv, kty, x and y. If alg leaked into the
            // canonical form the digest would differ from the server's.
            var key = new EcPublicJsonWebKey(TestX, TestY);
            var canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + TestX + "\",\"y\":\"" + TestY + "\"}";

            Assert.Equal(Hex.Sha256Hex(canonical), key.Thumbprint);
        }

        [Fact]
        public void Thumbprint_IsStableAcrossEquivalentConstructions()
        {
            var fromCoordinates = new EcPublicJsonWebKey(
                Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
                Enumerable.Range(33, 32).Select(value => (byte)value).ToArray());
            var fromStrings = new EcPublicJsonWebKey(TestX, TestY);

            Assert.Equal(fromStrings.Thumbprint, fromCoordinates.Thumbprint);
            Assert.Equal(TestX, fromCoordinates.X);
            Assert.Equal(TestY, fromCoordinates.Y);
        }

        [Fact]
        public void Constructor_RejectsCoordinatesThatAreNotThirtyTwoBytes()
        {
            var error = Assert.Throws<InstallationKeyException>(
                () => new EcPublicJsonWebKey(new byte[31], new byte[32]));

            Assert.Equal("INVALID_PUBLIC_KEY", error.Code);
        }

        [Fact]
        public void Write_EmitsTheMembersTheServerRequires()
        {
            var key = new EcPublicJsonWebKey(TestX, TestY);

            using var buffer = new System.IO.MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                key.Write(writer);
            }

            using var document = JsonDocument.Parse(buffer.ToArray());
            var root = document.RootElement;

            Assert.Equal("EC", root.GetProperty("kty").GetString());
            Assert.Equal("P-256", root.GetProperty("crv").GetString());
            Assert.Equal("ES256", root.GetProperty("alg").GetString());
            Assert.Equal(TestX, root.GetProperty("x").GetString());
            Assert.Equal(TestY, root.GetProperty("y").GetString());
        }

        [Fact]
        public void Parse_RejectsAKeyThatIsNotEcP256Es256()
        {
            using var document = JsonDocument.Parse(
                "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"n\":\"AQAB\",\"e\":\"AQAB\"}");

            Assert.Throws<InstallationKeyException>(() => EcPublicJsonWebKey.Parse(document.RootElement));
        }
    }
}
