using System;
using System.Text;
using DeviceTrust.Client.Internal;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>Encoding tests for the only encoding this protocol puts on the wire.</summary>
    public sealed class Base64UrlTests
    {
        [Fact]
        public void Encode_NeverEmitsPadding()
        {
            for (var length = 1; length <= 64; length++)
            {
                var encoded = Base64Url.Encode(new byte[length]);
                Assert.DoesNotContain("=", encoded, StringComparison.Ordinal);
            }
        }

        [Fact]
        public void Encode_UsesTheUrlSafeAlphabet()
        {
            // 0xFB 0xFF encodes to "+/8" in standard base64, which exercises both
            // substituted characters at once.
            var encoded = Base64Url.Encode(new byte[] { 0xFB, 0xFF, 0xFF });

            Assert.DoesNotContain("+", encoded, StringComparison.Ordinal);
            Assert.DoesNotContain("/", encoded, StringComparison.Ordinal);
        }

        [Fact]
        public void Decode_RoundTripsEveryLength()
        {
            var random = new Random(20260905);
            for (var length = 1; length <= 128; length++)
            {
                var original = new byte[length];
                random.NextBytes(original);

                Assert.Equal(original, Base64Url.Decode(Base64Url.Encode(original)));
            }
        }

        [Fact]
        public void Decode_AcceptsPaddedInput()
        {
            var bytes = Encoding.UTF8.GetBytes("padding tolerated");
            var padded = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');

            Assert.Equal(bytes, Base64Url.Decode(padded));
        }

        [Fact]
        public void Decode_RejectsAnImpossibleLength()
        {
            Assert.Throws<FormatException>(() => Base64Url.Decode("abcde"));
        }
    }
}
