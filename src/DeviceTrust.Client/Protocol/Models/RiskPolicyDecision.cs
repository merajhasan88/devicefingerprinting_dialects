using System;
using System.Collections.Generic;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>One reason contributing to a relationship-risk score.</summary>
    public sealed class RiskPolicyReason
    {
        internal RiskPolicyReason(string code, int points, string message)
        {
            Code = code;
            Points = points;
            Message = message;
        }

        /// <summary>The reason code.</summary>
        public string Code { get; }

        /// <summary>Points this reason contributed.</summary>
        public int Points { get; }

        /// <summary>A human-readable explanation.</summary>
        public string Message { get; }
    }

    /// <summary>
    /// The server-side device/account relationship risk decision.
    /// </summary>
    /// <remarks>
    /// This layer is separate from native integrity: it scores only
    /// server-observed relationships — installations per device, accounts per
    /// device, devices per account, reinstall velocity, status — and adds no
    /// hardware fingerprint attributes and no PII.
    /// </remarks>
    public sealed class RiskPolicyDecision
    {
        private RiskPolicyDecision(
            string decisionId,
            string eventType,
            string mode,
            int score,
            string recommendedAction,
            string effectiveAction,
            bool enforced,
            IReadOnlyList<RiskPolicyReason> reasons,
            IReadOnlyDictionary<string, JsonElement> context,
            IReadOnlyDictionary<string, JsonElement> thresholds,
            string createdAt)
        {
            DecisionId = decisionId;
            EventType = eventType;
            Mode = mode;
            Score = score;
            RecommendedAction = recommendedAction;
            EffectiveAction = effectiveAction;
            Enforced = enforced;
            Reasons = reasons;
            Context = context;
            Thresholds = thresholds;
            CreatedAt = createdAt;
        }

        /// <summary>The persisted decision id, or <c>not-persisted</c>.</summary>
        public string DecisionId { get; }

        /// <summary>The event that triggered the evaluation.</summary>
        public string EventType { get; }

        /// <summary><c>observe</c> or <c>enforce</c>.</summary>
        public string Mode { get; }

        /// <summary>The relationship-risk score.</summary>
        public int Score { get; }

        /// <summary>What the policy recommends.</summary>
        public string RecommendedAction { get; }

        /// <summary>What the server actually did, which in observe mode is <c>allow</c>.</summary>
        public string EffectiveAction { get; }

        /// <summary>Whether the recommendation was enforced.</summary>
        public bool Enforced { get; }

        /// <summary>The reasons that produced the score.</summary>
        public IReadOnlyList<RiskPolicyReason> Reasons { get; }

        /// <summary>The relationship counts behind the score.</summary>
        public IReadOnlyDictionary<string, JsonElement> Context { get; }

        /// <summary>The step-up, review and block thresholds in force.</summary>
        public IReadOnlyDictionary<string, JsonElement> Thresholds { get; }

        /// <summary>When the decision was made.</summary>
        public string CreatedAt { get; }

        /// <summary>Parses a policy decision object.</summary>
        public static RiskPolicyDecision Parse(JsonElement element)
        {
            var reasons = new List<RiskPolicyReason>();
            if (element.ValueKind == JsonValueKind.Object
                && element.TryGetProperty("reasons", out var rawReasons)
                && rawReasons.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in rawReasons.EnumerateArray())
                {
                    reasons.Add(new RiskPolicyReason(
                        Json.GetString(item, "code") ?? "unknown",
                        Json.GetInt32(item, "points"),
                        Json.GetString(item, "message") ?? string.Empty));
                }
            }

            return new RiskPolicyDecision(
                Json.GetString(element, "decision_id") ?? "not-persisted",
                Json.GetString(element, "event_type") ?? "unknown",
                Json.GetString(element, "mode") ?? "observe",
                Json.GetInt32(element, "score"),
                Json.GetString(element, "recommended_action") ?? "allow",
                Json.GetString(element, "effective_action") ?? "allow",
                Json.GetBoolean(element, "enforced"),
                reasons,
                Json.ToDictionary(Json.GetObject(element, "context") ?? default),
                Json.ToDictionary(Json.GetObject(element, "thresholds") ?? default),
                Json.GetString(element, "created_at") ?? string.Empty);
        }
    }
}
