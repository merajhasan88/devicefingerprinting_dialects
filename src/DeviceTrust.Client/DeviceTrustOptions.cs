using System;

namespace DeviceTrust.Client
{
    /// <summary>
    /// Configuration for a <see cref="DeviceTrustClient"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="BaseUrl"/> has no default and never will. The Flutter client
    /// takes it only from <c>--dart-define=API_BASE_URL</c> and fails loudly
    /// with <c>api_base_url_missing</c> when it is absent; this SDK behaves
    /// identically so that a .NET build can never ship pointing at a lab, a
    /// colleague's laptop, or another customer's environment.
    /// </para>
    /// </remarks>
    public sealed class DeviceTrustOptions
    {
        /// <summary>Environment variable holding the API base URL.</summary>
        public const string BaseUrlEnvironmentVariable = "API_BASE_URL";

        /// <summary>Environment variable holding a foreign access token for boundary tests.</summary>
        public const string StolenAccessTokenEnvironmentVariable = "STOLEN_ACCESS_TOKEN";

        /// <summary>Environment variable holding a foreign refresh token for boundary tests.</summary>
        public const string StolenRefreshTokenEnvironmentVariable = "STOLEN_REFRESH_TOKEN";

        /// <summary>
        /// The HTTPS endpoint of the device-trust server, for example
        /// <c>https://device-trust.example.com</c>. A trailing slash is trimmed.
        /// A path prefix is supported and is included in the signed access-proof
        /// path, because the server compares the proof against its own
        /// <c>request.path</c>.
        /// </summary>
        public string? BaseUrl { get; set; }

        /// <summary>
        /// Overrides the platform reported at registration. Leave null to use the
        /// platform the integrity collector actually measures, which is the
        /// honest choice: the platform you claim should be the platform you can
        /// produce measurements for.
        /// </summary>
        public string? Platform { get; set; }

        /// <summary>How long any single HTTP call may take. Defaults to 15 seconds, as in the Flutter client.</summary>
        public TimeSpan NetworkTimeout { get; set; } = TimeSpan.FromSeconds(15);

        /// <summary>
        /// A foreign access token injected for the stolen-token boundary test,
        /// mirroring <c>--dart-define=STOLEN_ACCESS_TOKEN</c>. Never used by
        /// ordinary flows.
        /// </summary>
        public string? StolenAccessToken { get; set; }

        /// <summary>
        /// A foreign refresh token injected for the stolen-token boundary test,
        /// mirroring <c>--dart-define=STOLEN_REFRESH_TOKEN</c>.
        /// </summary>
        public string? StolenRefreshToken { get; set; }

        /// <summary>
        /// Reads options from the process environment, mirroring the Flutter
        /// client's build-time defines.
        /// </summary>
        public static DeviceTrustOptions FromEnvironment()
        {
            return new DeviceTrustOptions
            {
                BaseUrl = Environment.GetEnvironmentVariable(BaseUrlEnvironmentVariable),
                StolenAccessToken = Environment.GetEnvironmentVariable(StolenAccessTokenEnvironmentVariable),
                StolenRefreshToken = Environment.GetEnvironmentVariable(StolenRefreshTokenEnvironmentVariable),
            };
        }

        /// <summary>
        /// Returns the base URI, throwing <c>api_base_url_missing</c> when no
        /// endpoint was configured.
        /// </summary>
        public Uri ResolveBaseUri()
        {
            if (string.IsNullOrWhiteSpace(BaseUrl))
            {
                throw new DeviceTrustConfigurationException(
                    "No API base URL was configured. Set " + BaseUrlEnvironmentVariable
                    + "=https://<host> in the environment or ApiBaseUrl in appsettings.json.",
                    "api_base_url_missing");
            }

            var trimmed = BaseUrl!.Trim().TrimEnd('/');
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw new DeviceTrustConfigurationException(
                    "The API base URL '" + BaseUrl + "' is not an absolute http(s) URL.",
                    "api_base_url_invalid");
            }

            return uri;
        }
    }
}
