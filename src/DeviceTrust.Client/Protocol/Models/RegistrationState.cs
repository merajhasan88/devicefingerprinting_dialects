using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>The server's answer to <c>POST /v1/installations/register</c>.</summary>
    public sealed class RegistrationState
    {
        private RegistrationState(
            string installationId,
            string deviceId,
            string keyThumbprint,
            string keyAlgorithm,
            string method,
            string confidence,
            bool isReinstallCorrelation)
        {
            InstallationId = installationId;
            DeviceId = deviceId;
            KeyThumbprint = keyThumbprint;
            KeyAlgorithm = keyAlgorithm;
            Method = method;
            Confidence = confidence;
            IsReinstallCorrelation = isReinstallCorrelation;
        }

        /// <summary>
        /// The canonical installation id. It may differ from the one submitted:
        /// when the server already knows this public key it answers with the
        /// installation the key is bound to, and the client must adopt it.
        /// </summary>
        public string InstallationId { get; }

        /// <summary>The recognised device this installation belongs to.</summary>
        public string DeviceId { get; }

        /// <summary>The server-computed RFC 7638 thumbprint of the registered key.</summary>
        public string KeyThumbprint { get; }

        /// <summary>The key algorithm the server recorded, normally <c>ES256</c>.</summary>
        public string KeyAlgorithm { get; }

        /// <summary>How the device was recognised: <c>exact_key</c>, <c>reinstall_hint</c> or <c>new_device</c>.</summary>
        public string Method { get; }

        /// <summary>The confidence attached to that recognition.</summary>
        public string Confidence { get; }

        /// <summary>Whether this registration was correlated to an existing device by a reinstall hint.</summary>
        public bool IsReinstallCorrelation { get; }

        /// <summary>Parses a registration response.</summary>
        public static RegistrationState Parse(JsonElement element)
        {
            var recognition = Json.GetObject(element, "recognition") ?? default;
            return new RegistrationState(
                Json.RequireString(element, "installation_id"),
                Json.RequireString(element, "device_id"),
                Json.RequireString(element, "key_thumbprint"),
                Json.GetString(element, "key_algorithm") ?? "unknown",
                Json.GetString(recognition, "method") ?? "unknown",
                Json.GetString(recognition, "confidence") ?? "unknown",
                Json.GetBoolean(recognition, "is_reinstall_correlation"));
        }
    }
}
