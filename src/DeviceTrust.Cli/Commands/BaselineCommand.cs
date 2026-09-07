using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Integrity;

namespace DeviceTrust.Cli.Commands
{
    /// <summary>
    /// Derives a build's writable-executable baseline from a connected device.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists so that pinning the baseline is a build step rather than
    /// something a person is trusted to remember. It needs no server, no account
    /// and no network — only a device with the build installed — so it drops into
    /// a release pipeline next to whatever already computes the APK hash, and it
    /// exits non-zero when it cannot produce an answer it believes.
    /// </para>
    /// <para>
    /// It refuses rather than guesses. If the reserved total is not identical
    /// across every run, no baseline is emitted: the likeliest cause is that
    /// something else was running in the process during measurement, and a
    /// baseline derived from that would permanently tolerate it.
    /// </para>
    /// </remarks>
    public static class BaselineCommand
    {
        private const string Package = "com.example.devicefingerprinting_dotnet";
        private const string Activity = Package + "/.MainActivity";

        /// <summary>Runs the command.</summary>
        public static async Task<int> RunAsync(
            string? serial,
            int runs,
            string? apkSha256,
            string? endpoint,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                Console.Error.WriteLine(
                    "An endpoint is required (--base-url or API_BASE_URL). The baseline has to be "
                    + "measured at the moment the integrity report is composed, which means running a "
                    + "real scan; measuring at launch reports a materially smaller number, because "
                    + "the runtime has not yet compiled the network, TLS and signing paths.");
                return 2;
            }

            if (runs < 4)
            {
                Console.Error.WriteLine("At least four runs are required; a baseline from fewer means nothing.");
                return 2;
            }

            var device = serial ?? await ResolveSingleDeviceAsync(cancellationToken).ConfigureAwait(false);
            if (device is null)
            {
                Console.Error.WriteLine(
                    "No device selected. Pass --device <serial>, or connect exactly one device.");
                return 2;
            }

            Report.Heading("Measuring the writable-executable baseline");
            Report.Field("Device", device);
            Report.Field("Runs", runs);
            Report.Field("Endpoint", endpoint!);
            Report.Line("Each run is a cold start followed by a full scan, so the measurement is taken");
            Report.Line("at the moment the integrity report is composed -- the same moment the server");
            Report.Line("scores. Measuring at launch instead reports roughly a third of this figure.");

            var observations = new List<WritableExecutableObservation>();
            for (var index = 1; index <= runs; index++)
                {
                var observation = await MeasureOnceAsync(device, endpoint!, cancellationToken).ConfigureAwait(false);
                if (observation is null)
                {
                    Console.Error.WriteLine("Run " + index.ToString(CultureInfo.InvariantCulture)
                                            + " produced no measurement. Is the build installed on " + device + "?");
                    return 3;
                }

                Report.Line("run " + index.ToString(CultureInfo.InvariantCulture) + ": "
                            + observation.Value.Bytes.ToString(CultureInfo.InvariantCulture)
                            + " bytes, classes " + observation.Value.SizeClasses);
                observations.Add(observation.Value);
            }

            var baseline = WritableExecutableBaseline.Compute(observations);
            if (!baseline.IsUsable)
            {
                Report.Heading("No baseline produced");
                Report.Line(baseline.Rejection!);
                return 1;
            }

            Report.Heading("Baseline");
            Report.Field("Reserved total", baseline.Bytes.ToString(CultureInfo.InvariantCulture) + " bytes");
            Report.Field("Granularity", baseline.Granularity.ToString(CultureInfo.InvariantCulture) + " bytes");
            Report.Field("Blocks", (baseline.Bytes / baseline.Granularity).ToString(CultureInfo.InvariantCulture));
            Report.Field("Agreeing runs", baseline.Observations);

            Console.WriteLine();
            Console.WriteLine("# Pin these alongside the APK hash for this build.");
            Console.WriteLine(baseline.ToEnvironmentSettings(apkSha256 ?? "<apk-sha256>"));
            return 0;
        }

        private static async Task<WritableExecutableObservation?> MeasureOnceAsync(
            string device,
            string endpoint,
            CancellationToken cancellationToken)
        {
            await AdbAsync(device, cancellationToken, "shell", "am", "force-stop", Package).ConfigureAwait(false);
            await AdbAsync(device, cancellationToken, "logcat", "-c").ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            await AdbAsync(device, cancellationToken,
                "shell", "am", "start", "-n", Activity,
                "-e", "action", "scan", "-e", "api_base_url", endpoint).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(32), cancellationToken).ConfigureAwait(false);

            var log = await AdbAsync(device, cancellationToken, "logcat", "-d", "-s", "DTHARNESS")
                .ConfigureAwait(false);
            foreach (var line in log.Split('\n'))
            {
                var marker = line.IndexOf("WXREPORT ", StringComparison.Ordinal);
                if (marker < 0)
                {
                    continue;
                }

                long bytes = 0;
                var classes = string.Empty;
                foreach (var field in line.Substring(marker + "WXREPORT ".Length).Trim().Split(' '))
                {
                    var separator = field.IndexOf('=');
                    if (separator < 0)
                    {
                        continue;
                    }

                    var name = field.Substring(0, separator);
                    var value = field.Substring(separator + 1);
                    if (name == "bytes")
                    {
                        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out bytes);
                    }
                    else if (name == "classes")
                    {
                        classes = value == "none" ? string.Empty : value;
                    }
                }

                return new WritableExecutableObservation(bytes, classes);
            }

            return null;
        }

        private static async Task<string?> ResolveSingleDeviceAsync(CancellationToken cancellationToken)
        {
            var output = await AdbAsync(null, cancellationToken, "devices").ConfigureAwait(false);
            var serials = output.Split('\n')
                .Skip(1)
                .Select(line => line.Trim())
                .Where(line => line.EndsWith("\tdevice", StringComparison.Ordinal))
                .Select(line => line.Split('\t')[0])
                .ToList();
            return serials.Count == 1 ? serials[0] : null;
        }

        private static async Task<string> AdbAsync(
            string? device,
            CancellationToken cancellationToken,
            params string[] arguments)
        {
            var start = new ProcessStartInfo("adb")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };

            if (device is not null)
            {
                start.ArgumentList.Add("-s");
                start.ArgumentList.Add(device);
            }

            foreach (var argument in arguments)
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)
                                ?? throw new InvalidOperationException("adb could not be started; is it on PATH?");
            var output = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return output;
        }
    }
}
