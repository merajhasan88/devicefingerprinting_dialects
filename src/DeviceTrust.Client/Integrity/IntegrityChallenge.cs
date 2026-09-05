using System.Collections.Generic;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>The server's integrity challenge: which probes to run, and the nonce that binds the answer to it.</summary>
    public sealed class IntegrityChallenge
    {
        private IntegrityChallenge(
            string challengeId,
            string nonce,
            string platform,
            IReadOnlyList<string> requiredProbes,
            string expiresAt,
            string serverTime,
            int collectorPolicyVersion)
        {
            ChallengeId = challengeId;
            Nonce = nonce;
            Platform = platform;
            RequiredProbes = requiredProbes;
            ExpiresAt = expiresAt;
            ServerTime = serverTime;
            CollectorPolicyVersion = collectorPolicyVersion;
        }

        /// <summary>The challenge id, single-use.</summary>
        public string ChallengeId { get; }

        /// <summary>A 32-byte base64url nonce the report must echo.</summary>
        public string Nonce { get; }

        /// <summary>The platform the server expects measurements for.</summary>
        public string Platform { get; }

        /// <summary>
        /// The probes the server requires. Omitting one is rejected outright, and
        /// a required probe that reports a non-<c>ok</c> status is penalised, so
        /// a collector must attempt every name it is given.
        /// </summary>
        public IReadOnlyList<string> RequiredProbes { get; }

        /// <summary>When the challenge expires.</summary>
        public string ExpiresAt { get; }

        /// <summary>The server's clock at issue time.</summary>
        public string ServerTime { get; }

        /// <summary>The collector policy version the server is running.</summary>
        public int CollectorPolicyVersion { get; }

        /// <summary>Parses an integrity challenge response.</summary>
        public static IntegrityChallenge Parse(JsonElement element)
        {
            return new IntegrityChallenge(
                Json.RequireString(element, "challenge_id"),
                Json.RequireString(element, "nonce"),
                Json.RequireString(element, "platform"),
                Json.GetStringArray(element, "required_probes"),
                Json.GetString(element, "expires_at") ?? string.Empty,
                Json.GetString(element, "server_time") ?? string.Empty,
                Json.GetInt32(element, "collector_policy_version", 1));
        }
    }
}
