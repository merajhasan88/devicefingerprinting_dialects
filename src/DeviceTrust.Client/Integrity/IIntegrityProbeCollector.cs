using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// Collects the native measurements the server asked for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the .NET analogue of the Flutter client's <c>integrity_v1</c>
    /// method channel. The flow is server-driven: the server picks the probes,
    /// the collector runs exactly those, the installation key signs the complete
    /// report, and the server scores the raw measurements. The client never
    /// computes or sends a score.
    /// </para>
    /// <para>
    /// A collector must supply measurements appropriate to the platform it
    /// claims in <see cref="Platform"/>. Windows signals are a different design
    /// from Android's, not a translation of them, and the honest way to report a
    /// probe this platform cannot run is
    /// <see cref="ProbeResult.Unsupported(string)"/>.
    /// </para>
    /// </remarks>
    public interface IIntegrityProbeCollector
    {
        /// <summary>
        /// The platform these measurements describe. This is also the platform
        /// the client registers under, so that the identity a device claims and
        /// the measurements it can produce always agree.
        /// </summary>
        string Platform { get; }

        /// <summary>The collector's version, recorded in every report.</summary>
        int CollectorVersion { get; }

        /// <summary>Runs the requested probes and echoes the challenge nonce.</summary>
        Task<IntegrityCollection> CollectAsync(
            IReadOnlyList<string> requiredProbes,
            string challengeNonce,
            CancellationToken cancellationToken = default);
    }
}
