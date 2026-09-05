using System;
using System.Collections.Generic;
using System.Text.Json;
using DeviceTrust.Client;
using DeviceTrust.Client.Internal;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>Configuration and error-envelope behaviour.</summary>
    public sealed class OptionsAndErrorTests
    {
        [Fact]
        public void ResolveBaseUri_WithNoEndpointFailsWithApiBaseUrlMissing()
        {
            // The Flutter client fails a build with no --dart-define=API_BASE_URL
            // and this SDK fails a run with no endpoint, so a .NET build can never
            // silently point at the wrong environment.
            var options = new DeviceTrustOptions();

            var error = Assert.Throws<DeviceTrustConfigurationException>(() => options.ResolveBaseUri());

            Assert.Equal("api_base_url_missing", error.Code);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void ResolveBaseUri_TreatsBlankAsMissing(string value)
        {
            var options = new DeviceTrustOptions { BaseUrl = value };

            Assert.Equal("api_base_url_missing", Assert.Throws<DeviceTrustConfigurationException>(
                () => options.ResolveBaseUri()).Code);
        }

        [Theory]
        [InlineData("device-trust.example.com")]
        [InlineData("ftp://device-trust.example.com")]
        [InlineData("not a url")]
        public void ResolveBaseUri_RejectsAnythingThatIsNotAnAbsoluteHttpUrl(string value)
        {
            var options = new DeviceTrustOptions { BaseUrl = value };

            Assert.Equal("api_base_url_invalid", Assert.Throws<DeviceTrustConfigurationException>(
                () => options.ResolveBaseUri()).Code);
        }

        [Fact]
        public void ResolveBaseUri_TrimsATrailingSlash()
        {
            var options = new DeviceTrustOptions { BaseUrl = "https://device-trust.example.com/" };

            Assert.Equal("https://device-trust.example.com/", options.ResolveBaseUri().AbsoluteUri);
            Assert.Equal("/", options.ResolveBaseUri().AbsolutePath);
        }

        [Fact]
        public void ApiException_ReadsTheCodeFromTheNestedEnvelope()
        {
            // The envelope is {"error": {"code": ...}}. A client reading a flat
            // top-level "code" gets null for every rejection, and every piece of
            // control flow that keys on the code silently stops working.
            using var document = JsonDocument.Parse(
                "{\"error\":{\"code\":\"access_proof_replay\",\"message\":\"already used\","
                + "\"details\":{\"nonce\":\"abc\"}}}");
            var envelope = Json.GetObject(document.RootElement, "error");

            Assert.NotNull(envelope);
            Assert.Equal("access_proof_replay", Json.GetString(envelope!.Value, "code"));
            Assert.Equal("already used", Json.GetString(envelope.Value, "message"));

            var details = Json.ToDictionary(Json.GetObject(envelope.Value, "details")!.Value);
            var exception = new DeviceTrustApiException("already used", 401, "access_proof_replay", details);

            Assert.Equal(401, exception.StatusCode);
            Assert.Equal("access_proof_replay", exception.Code);
            Assert.True(exception.Details.ContainsKey("nonce"));
        }

        [Fact]
        public void ApiException_WithNoDetailsExposesAnEmptyDictionary()
        {
            var exception = new DeviceTrustApiException("rejected", 403, "integrity_blocked");

            Assert.Empty(exception.Details);
            Assert.Contains("integrity_blocked", exception.ToString(), StringComparison.Ordinal);
        }

        [Fact]
        public void FromEnvironment_ReadsTheDocumentedVariableNames()
        {
            Assert.Equal("API_BASE_URL", DeviceTrustOptions.BaseUrlEnvironmentVariable);
            Assert.Equal("STOLEN_ACCESS_TOKEN", DeviceTrustOptions.StolenAccessTokenEnvironmentVariable);
            Assert.Equal("STOLEN_REFRESH_TOKEN", DeviceTrustOptions.StolenRefreshTokenEnvironmentVariable);
        }
    }

    /// <summary>Tests for the reinstall hint's normalisation and domain separation.</summary>
    public sealed class ReinstallHintTests
    {
        [Fact]
        public void FromRawIdentifier_HashesWithTheSharedDomainSeparator()
        {
            // The Flutter client computes
            // sha256("device-recognition-hint-v1|android_id|<lowercased>"). A .NET
            // client that salted differently would never correlate a reinstall to
            // the same device record.
            var hint = ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", "AbCdEf01");

            Assert.NotNull(hint);
            Assert.Equal("android_id_sha256", hint!.Kind);
            Assert.Equal(Hex.Sha256Hex("device-recognition-hint-v1|android_id|abcdef01"), hint.Value);
        }

        [Fact]
        public void FromRawIdentifier_NormalisesCaseAndSurroundingWhitespace()
        {
            var upper = ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", "  ABCDEF01 ");
            var lower = ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", "abcdef01");

            Assert.Equal(lower!.Value, upper!.Value);
        }

        [Fact]
        public void FromRawIdentifier_ReturnsNullWhenThePlatformHasNoIdentifier()
        {
            // A missing hint must never block registration; the device simply
            // enrols as new.
            Assert.Null(ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", null));
            Assert.Null(ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", "   "));
        }

        [Fact]
        public void FromRawIdentifier_SeparatesDifferentSources()
        {
            var android = ReinstallHint.FromRawIdentifier("android_id_sha256", "android_id", "shared-value");
            var apple = ReinstallHint.FromRawIdentifier("idfv_sha256", "idfv", "shared-value");

            Assert.NotEqual(android!.Value, apple!.Value);
        }
    }
}
