using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Protocol;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Tests for the per-request proof of possession.
    /// </summary>
    /// <remarks>
    /// The server parses the proof only after verifying the signature over the
    /// received bytes, so field order does not matter across languages. What does
    /// matter is that exactly these eight fields are present with these names and
    /// JSON types: a missing or misnamed field is rejected, and a timestamp sent
    /// as a string rather than a number fails with
    /// <c>invalid_access_proof_timestamp</c>.
    /// </remarks>
    public sealed class AccessProofTests
    {
        private const string EmptySha256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        [Fact]
        public void Serialize_ContainsExactlyTheEightProtocolFields()
        {
            var proof = Serialize();

            using var document = JsonDocument.Parse(proof);
            var names = new List<string>();
            foreach (var property in document.RootElement.EnumerateObject())
            {
                names.Add(property.Name);
            }

            Assert.Equal(
                new[]
                {
                    "access_token_sha256", "body_sha256", "installation_id", "method",
                    "nonce", "path", "timestamp", "version",
                },
                names);
        }

        [Fact]
        public void Serialize_WritesTimestampAndVersionAsNumbers()
        {
            using var document = JsonDocument.Parse(Serialize());
            var root = document.RootElement;

            Assert.Equal(JsonValueKind.Number, root.GetProperty("timestamp").ValueKind);
            Assert.Equal(JsonValueKind.Number, root.GetProperty("version").ValueKind);
            Assert.Equal(1, root.GetProperty("version").GetInt32());
            Assert.Equal(1_700_000_000L, root.GetProperty("timestamp").GetInt64());
        }

        [Fact]
        public void Serialize_UppercasesNothingItselfButPreservesWhatItIsGiven()
        {
            // Normalisation is the caller's job, so that a fixture can sign a
            // method deliberately different from the one it sends.
            var proof = Serialize(method: "get");

            using var document = JsonDocument.Parse(proof);
            Assert.Equal("get", document.RootElement.GetProperty("method").GetString());
        }

        [Fact]
        public void BodyHash_OfNoBodyIsTheHashOfTheEmptyString()
        {
            Assert.Equal(EmptySha256, AccessProof.BodyHash(null));
            Assert.Equal(EmptySha256, AccessProof.BodyHash(Array.Empty<byte>()));
        }

        [Fact]
        public void BodyHash_CoversTheExactBytes()
        {
            var body = Encoding.UTF8.GetBytes("{\"amount\":1}");

            Assert.Equal(Hex.Sha256Hex(body), AccessProof.BodyHash(body));
            Assert.NotEqual(AccessProof.BodyHash(body), AccessProof.BodyHash(Encoding.UTF8.GetBytes("{\"amount\":2}")));
        }

        [Fact]
        public void CreateNonce_IsThirtyTwoBytesAndUnpadded()
        {
            var nonce = AccessProof.CreateNonce();

            Assert.DoesNotContain("=", nonce, StringComparison.Ordinal);
            Assert.Equal(AccessProof.NonceByteLength, Base64Url.Decode(nonce).Length);
        }

        [Fact]
        public void CreateNonce_DoesNotRepeat()
        {
            // The nonce is single-use and the server refuses a repeat with
            // access_proof_replay, so a collision would look like an attack.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < 512; index++)
            {
                Assert.True(seen.Add(AccessProof.CreateNonce()));
            }
        }

        [Fact]
        public void CurrentTimestamp_IsUnixSecondsInUtc()
        {
            var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var timestamp = AccessProof.CurrentTimestamp();

            Assert.InRange(timestamp, before - 2, before + 2);
        }

        private static byte[] Serialize(string method = "POST")
        {
            return AccessProof.Serialize(
                accessTokenSha256Hex: Hex.Sha256Hex("token"),
                bodySha256Hex: EmptySha256,
                installationId: "6a5f5cf7-7c1d-4c7f-9d0a-2d2a1c2f4d8e",
                method: method,
                nonce: AccessProof.CreateNonce(),
                path: "/v1/account/protected-echo",
                timestamp: 1_700_000_000L);
        }
    }
}
