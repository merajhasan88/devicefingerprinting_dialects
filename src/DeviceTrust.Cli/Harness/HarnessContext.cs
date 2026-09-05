using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client;
using DeviceTrust.Client.Integrity;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Storage;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>
    /// Creates the simulated devices a test run needs and cleans up after them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Several checks need two <i>different</i> installations — a stolen access
    /// token is only interesting when the device replaying it holds a different
    /// key. On real hardware that is two handsets; here it is two independent
    /// software keys in two directories.
    /// </para>
    /// <para>
    /// This proves the protocol binding: the server refuses a token presented
    /// with a signature from the wrong installation key. It does not prove
    /// hardware binding, because a software key can be copied. The handset
    /// battery on real devices is what covers that, and this harness does not
    /// claim to replace it.
    /// </para>
    /// </remarks>
    public sealed class HarnessContext : IDisposable
    {
        private readonly HarnessConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly List<IDisposable> _disposables = new List<IDisposable>();
        private readonly List<string> _temporaryDirectories = new List<string>();

        /// <summary>Creates a context for one run.</summary>
        public HarnessContext(HarnessConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _httpClient = new HttpClient();
            _disposables.Add(_httpClient);
        }

        /// <summary>
        /// Creates a client backed by a fresh, throwaway software key: a new
        /// "device" that has never been seen by the server.
        /// </summary>
        public DeviceTrustClient CreateEphemeralDevice(
            string label,
            ConformanceProbeCollector? collector = null)
        {
            var directory = Path.Combine(
                Path.GetTempPath(),
                "devicetrust-harness",
                DateTime.UtcNow.ToString("yyyyMMddHHmmssfff", CultureInfo.InvariantCulture) + "-" + label + "-"
                + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(directory);
            _temporaryDirectories.Add(directory);
            return CreateClient(directory, collector ?? new ConformanceProbeCollector());
        }

        /// <summary>Creates the client that uses the configured, persistent state directory.</summary>
        public DeviceTrustClient CreatePersistentDevice(IIntegrityProbeCollector? collector)
        {
            Directory.CreateDirectory(_configuration.StateDirectory);
            return CreateClient(_configuration.StateDirectory, collector);
        }

        /// <summary>Runs an operation expected to fail, and returns the failure for assertions.</summary>
        public static async Task<DeviceTrustApiException> ExpectApiFailureAsync(
            Func<Task> operation,
            string whatWasAttempted)
        {
            try
            {
                await operation().ConfigureAwait(false);
            }
            catch (DeviceTrustApiException error)
            {
                return error;
            }

            throw new CheckFailedException(
                whatWasAttempted + " was accepted by the server, which is a security failure, not a test failure.");
        }

        /// <inheritdoc />
        public void Dispose()
        {
            foreach (var disposable in _disposables)
            {
                disposable.Dispose();
            }

            foreach (var directory in _temporaryDirectories)
            {
                try
                {
                    if (Directory.Exists(directory))
                    {
                        Directory.Delete(directory, recursive: true);
                    }
                }
                catch (IOException)
                {
                    // A leftover temp directory is untidy, never harmful, and
                    // must not turn a passing run into a failing one.
                }
            }
        }

        private DeviceTrustClient CreateClient(string directory, IIntegrityProbeCollector? collector)
        {
            var keyStore = new SoftwareInstallationKeyStore(
                Path.Combine(directory, "installation-key.p8"),
                acknowledgeNotHardwareBacked: true);
            _disposables.Add(keyStore);

            var options = _configuration.ToClientOptions();
            if (collector is null)
            {
                // Without a collector the client cannot report integrity, so it
                // needs to be told what platform it is claiming to be.
                options.Platform = "android";
            }

            var client = new DeviceTrustClient(
                options,
                keyStore,
                new FileInstallationStateStore(Path.Combine(directory, "state.json")),
                collector,
                _httpClient);
            _disposables.Add(client);
            return client;
        }
    }
}
