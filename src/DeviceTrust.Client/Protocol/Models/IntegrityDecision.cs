using System.Collections.Generic;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>One scored integrity signal.</summary>
    public sealed class IntegrityRiskReason
    {
        internal IntegrityRiskReason(string code, int points, string message, bool hard)
        {
            Code = code;
            Points = points;
            Message = message;
            Hard = hard;
        }

        /// <summary>The reason code, for example <c>android_frida_runtime_artifact</c>.</summary>
        public string Code { get; }

        /// <summary>Points this signal contributed.</summary>
        public int Points { get; }

        /// <summary>A human-readable explanation.</summary>
        public string Message { get; }

        /// <summary>Whether this signal blocks on its own regardless of the total.</summary>
        public bool Hard { get; }
    }

    /// <summary>
    /// The server's verdict on a signed integrity report.
    /// </summary>
    /// <remarks>
    /// The score and verdict are computed entirely by the server from the raw
    /// measurements it was sent. The client's only inputs were the measurements
    /// and the signature over them.
    /// </remarks>
    public sealed class IntegrityDecision
    {
        private IntegrityDecision(
            string reportId,
            int score,
            string verdict,
            bool hardBlock,
            IReadOnlyList<IntegrityRiskReason> reasons,
            string mode,
            int freshForSeconds,
            string remoteAttestation,
            string createdAt)
        {
            ReportId = reportId;
            Score = score;
            Verdict = verdict;
            HardBlock = hardBlock;
            Reasons = reasons;
            Mode = mode;
            FreshForSeconds = freshForSeconds;
            RemoteAttestation = remoteAttestation;
            CreatedAt = createdAt;
        }

        /// <summary>The stored report id.</summary>
        public string ReportId { get; }

        /// <summary>The risk score, 0-100.</summary>
        public int Score { get; }

        /// <summary><c>trusted</c>, <c>elevated</c>, <c>review</c> or <c>block</c>.</summary>
        public string Verdict { get; }

        /// <summary>Whether a hard-block signal fired.</summary>
        public bool HardBlock { get; }

        /// <summary>Every signal the server scored.</summary>
        public IReadOnlyList<IntegrityRiskReason> Reasons { get; }

        /// <summary>The server's integrity mode: <c>observe</c> or <c>enforce</c>.</summary>
        public string Mode { get; }

        /// <summary>How long this report stays fresh enough to satisfy the gate.</summary>
        public int FreshForSeconds { get; }

        /// <summary>Always <c>not_used</c>: this design deliberately has no Play Integrity or App Attest.</summary>
        public string RemoteAttestation { get; }

        /// <summary>When the decision was made.</summary>
        public string CreatedAt { get; }

        /// <summary>Parses an integrity decision object.</summary>
        public static IntegrityDecision Parse(JsonElement element)
        {
            var reasons = new List<IntegrityRiskReason>();
            if (element.ValueKind == JsonValueKind.Object
                && element.TryGetProperty("reasons", out var rawReasons)
                && rawReasons.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in rawReasons.EnumerateArray())
                {
                    reasons.Add(new IntegrityRiskReason(
                        Json.GetString(item, "code") ?? "unknown",
                        Json.GetInt32(item, "points"),
                        Json.GetString(item, "message") ?? string.Empty,
                        Json.GetBoolean(item, "hard")));
                }
            }

            return new IntegrityDecision(
                Json.GetString(element, "report_id") ?? string.Empty,
                Json.GetInt32(element, "score"),
                Json.GetString(element, "verdict") ?? "unknown",
                Json.GetBoolean(element, "hard_block"),
                reasons,
                Json.GetString(element, "mode") ?? "observe",
                Json.GetInt32(element, "fresh_for_seconds"),
                Json.GetString(element, "remote_attestation") ?? "not_used",
                Json.GetString(element, "created_at") ?? string.Empty);
        }
    }
}
