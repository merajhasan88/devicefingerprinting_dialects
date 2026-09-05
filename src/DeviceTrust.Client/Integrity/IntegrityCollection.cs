using System;
using System.Collections.Generic;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// The complete output of one collection run, before the installation key
    /// signs it.
    /// </summary>
    public sealed class IntegrityCollection
    {
        /// <summary>Creates a collection result.</summary>
        public IntegrityCollection(
            string platform,
            int collectorVersion,
            string challengeNonceEcho,
            IReadOnlyDictionary<string, ProbeResult> probes)
        {
            Platform = platform ?? throw new ArgumentNullException(nameof(platform));
            ChallengeNonceEcho = challengeNonceEcho ?? throw new ArgumentNullException(nameof(challengeNonceEcho));
            Probes = probes ?? throw new ArgumentNullException(nameof(probes));
            CollectorVersion = collectorVersion;
        }

        /// <summary>The platform these measurements describe: <c>android</c> or <c>ios</c>.</summary>
        public string Platform { get; }

        /// <summary>The collector's own version, recorded with the report.</summary>
        public int CollectorVersion { get; }

        /// <summary>
        /// The challenge nonce echoed back. The client checks this against the
        /// nonce the server issued before it signs anything, so a collector that
        /// answered a stale or fabricated challenge is caught locally instead of
        /// producing a signed report that the server then has to reject.
        /// </summary>
        public string ChallengeNonceEcho { get; }

        /// <summary>The probe results, keyed by probe name.</summary>
        public IReadOnlyDictionary<string, ProbeResult> Probes { get; }
    }
}
