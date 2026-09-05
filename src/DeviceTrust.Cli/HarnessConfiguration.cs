using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DeviceTrust.Client;

namespace DeviceTrust.Cli
{
    /// <summary>
    /// Resolves the harness's settings from, in order of precedence, command-line
    /// switches, environment variables and <c>appsettings.json</c>.
    /// </summary>
    /// <remarks>
    /// The endpoint deliberately has no fallback at any layer. The Flutter client
    /// fails a build with no <c>--dart-define=API_BASE_URL</c>, and this harness
    /// fails a run with no endpoint, for the same reason: a default would let a
    /// test point at the wrong environment without anyone noticing.
    /// </remarks>
    public sealed class HarnessConfiguration
    {
        private HarnessConfiguration(
            string? apiBaseUrl,
            string stateDirectory,
            string integrityCollector,
            string? stolenAccessToken,
            string? stolenRefreshToken,
            bool verbose)
        {
            ApiBaseUrl = apiBaseUrl;
            StateDirectory = stateDirectory;
            IntegrityCollector = integrityCollector;
            StolenAccessToken = stolenAccessToken;
            StolenRefreshToken = stolenRefreshToken;
            Verbose = verbose;
        }

        /// <summary>The configured endpoint, or null when none was supplied.</summary>
        public string? ApiBaseUrl { get; }

        /// <summary>Where the installation key and local state are kept.</summary>
        public string StateDirectory { get; }

        /// <summary>Which integrity collector to use: <c>fixture</c>, <c>native</c> or <c>none</c>.</summary>
        public string IntegrityCollector { get; }

        /// <summary>A foreign access token for the stolen-token test.</summary>
        public string? StolenAccessToken { get; }

        /// <summary>A foreign refresh token for the stolen-token test.</summary>
        public string? StolenRefreshToken { get; }

        /// <summary>Whether to print each HTTP exchange.</summary>
        public bool Verbose { get; }

        /// <summary>Builds the configuration from parsed switches and the environment.</summary>
        public static HarnessConfiguration Resolve(IReadOnlyDictionary<string, string> switches)
        {
            var file = ReadSettingsFile();

            var baseUrl = First(
                Get(switches, "base-url"),
                Environment.GetEnvironmentVariable(DeviceTrustOptions.BaseUrlEnvironmentVariable),
                file.TryGetValue("ApiBaseUrl", out var configured) ? configured : null);

            var stateDirectory = First(
                Get(switches, "state-dir"),
                Environment.GetEnvironmentVariable("DEVICETRUST_STATE_DIR"),
                file.TryGetValue("StateDirectory", out var stateFromFile) ? stateFromFile : null)
                ?? Path.Combine(Directory.GetCurrentDirectory(), "devicetrust-state");

            var collector = First(
                Get(switches, "collector"),
                Environment.GetEnvironmentVariable("DEVICETRUST_COLLECTOR"),
                file.TryGetValue("IntegrityCollector", out var collectorFromFile) ? collectorFromFile : null)
                ?? "fixture";

            return new HarnessConfiguration(
                baseUrl,
                stateDirectory,
                collector.ToLowerInvariant(),
                First(
                    Get(switches, "stolen-access-token"),
                    Environment.GetEnvironmentVariable(DeviceTrustOptions.StolenAccessTokenEnvironmentVariable)),
                First(
                    Get(switches, "stolen-refresh-token"),
                    Environment.GetEnvironmentVariable(DeviceTrustOptions.StolenRefreshTokenEnvironmentVariable)),
                switches.ContainsKey("verbose"));
        }

        /// <summary>Turns the harness configuration into SDK options.</summary>
        public DeviceTrustOptions ToClientOptions()
        {
            return new DeviceTrustOptions
            {
                BaseUrl = ApiBaseUrl,
                StolenAccessToken = StolenAccessToken,
                StolenRefreshToken = StolenRefreshToken,
                NetworkTimeout = TimeSpan.FromSeconds(20),
            };
        }

        private static string? Get(IReadOnlyDictionary<string, string> switches, string name)
        {
            return switches.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;
        }

        private static string? First(params string?[] candidates)
        {
            foreach (var candidate in candidates)
            {
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate!.Trim();
                }
            }

            return null;
        }

        private static Dictionary<string, string> ReadSettingsFile()
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            if (!File.Exists(path))
            {
                return values;
            }

            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.String)
                    {
                        values[property.Name] = property.Value.GetString() ?? string.Empty;
                    }
                }
            }
            catch (JsonException)
            {
                // A malformed settings file must not silently become "no
                // endpoint configured"; the run will fail loudly with
                // api_base_url_missing, which points at the right place.
            }

            return values;
        }
    }
}
