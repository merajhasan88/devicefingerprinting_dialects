using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>The server's record of this installation and its device.</summary>
    public sealed class DeviceSummary
    {
        private DeviceSummary(
            string installationId,
            string deviceId,
            string platform,
            string deviceStatus,
            string keyThumbprint,
            string keyAlgorithm,
            string method,
            string confidence,
            int installationCount,
            int linkedAccountCount,
            string createdAt,
            string lastSeenAt,
            RiskPolicyDecision? policy)
        {
            InstallationId = installationId;
            DeviceId = deviceId;
            Platform = platform;
            DeviceStatus = deviceStatus;
            KeyThumbprint = keyThumbprint;
            KeyAlgorithm = keyAlgorithm;
            Method = method;
            Confidence = confidence;
            InstallationCount = installationCount;
            LinkedAccountCount = linkedAccountCount;
            CreatedAt = createdAt;
            LastSeenAt = lastSeenAt;
            Policy = policy;
        }

        /// <summary>This installation's id.</summary>
        public string InstallationId { get; }

        /// <summary>The recognised device id.</summary>
        public string DeviceId { get; }

        /// <summary>The platform recorded at registration.</summary>
        public string Platform { get; }

        /// <summary>Whether the device is <c>active</c>.</summary>
        public string DeviceStatus { get; }

        /// <summary>The registered key's thumbprint.</summary>
        public string KeyThumbprint { get; }

        /// <summary>The registered key's algorithm.</summary>
        public string KeyAlgorithm { get; }

        /// <summary>How this installation was originally recognised.</summary>
        public string Method { get; }

        /// <summary>The confidence of that recognition.</summary>
        public string Confidence { get; }

        /// <summary>How many installations the server has seen on this device.</summary>
        public int InstallationCount { get; }

        /// <summary>How many accounts are linked to this device.</summary>
        public int LinkedAccountCount { get; }

        /// <summary>When the installation was first seen.</summary>
        public string CreatedAt { get; }

        /// <summary>When the installation was last seen.</summary>
        public string LastSeenAt { get; }

        /// <summary>The relationship-risk decision for this device.</summary>
        public RiskPolicyDecision? Policy { get; }

        /// <summary>Parses a <c>GET /v1/device/me</c> response.</summary>
        public static DeviceSummary Parse(JsonElement element)
        {
            var recognition = Json.GetObject(element, "recognition") ?? default;
            var policy = Json.GetObject(element, "policy");
            return new DeviceSummary(
                Json.RequireString(element, "installation_id"),
                Json.RequireString(element, "device_id"),
                Json.GetString(element, "platform") ?? "unknown",
                Json.GetString(element, "device_status") ?? "active",
                Json.GetString(element, "key_thumbprint") ?? string.Empty,
                Json.GetString(element, "key_algorithm") ?? "unknown",
                Json.GetString(recognition, "method") ?? "unknown",
                Json.GetString(recognition, "confidence") ?? "unknown",
                Json.GetInt32(element, "installation_count"),
                Json.GetInt32(element, "linked_account_count"),
                Json.GetString(element, "created_at") ?? string.Empty,
                Json.GetString(element, "last_seen_at") ?? string.Empty,
                policy is null ? null : RiskPolicyDecision.Parse(policy.Value));
        }
    }
}
