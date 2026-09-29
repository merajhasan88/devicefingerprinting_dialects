using System.Text.Json;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;

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
            bool isReinstallCorrelation,
            KeySecurityState? keySecurity,
            bool stepUpKeyRegistered,
            bool? stepUpKeyMatches,
            StepUpKeyAuth? stepUpKeyAuth,
            bool? stepUpPolicyDowngrade)
        {
            InstallationId = installationId;
            DeviceId = deviceId;
            KeyThumbprint = keyThumbprint;
            KeyAlgorithm = keyAlgorithm;
            Method = method;
            Confidence = confidence;
            IsReinstallCorrelation = isReinstallCorrelation;
            KeySecurity = keySecurity;
            StepUpKeyRegistered = stepUpKeyRegistered;
            StepUpKeyMatches = stepUpKeyMatches;
            StepUpKeyAuth = stepUpKeyAuth;
            StepUpPolicyDowngrade = stepUpPolicyDowngrade;
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

        /// <summary>
        /// What the server has stored about the installation key's protection,
        /// or null from a server that predates the block.
        /// </summary>
        public KeySecurityState? KeySecurity { get; }

        /// <summary>Whether a step-up key is bound to this installation on the server.</summary>
        public bool StepUpKeyRegistered { get; }

        /// <summary>
        /// On re-registration, whether the step-up key this client offered is the
        /// bound one. Null when no key was offered, or on a first registration.
        /// </summary>
        /// <remarks>
        /// A step-up key binds only with a new installation key. Re-registration
        /// never attaches or replaces one — registration is unauthenticated, and
        /// otherwise anyone holding the public installation key could swap in a
        /// key they control — so a replaced local key shows up here as
        /// <c>false</c>, and re-enrolment is the only way to bind it.
        /// </remarks>
        public bool? StepUpKeyMatches { get; }

        /// <summary>The bound step-up key's auth as the server recorded it.</summary>
        public StepUpKeyAuth? StepUpKeyAuth { get; }

        /// <summary>Whether the bound key is weaker than the deployment's declared step-up mode.</summary>
        public bool? StepUpPolicyDowngrade { get; }

        /// <summary>Parses a registration response.</summary>
        public static RegistrationState Parse(JsonElement element)
        {
            var recognition = Json.GetObject(element, "recognition") ?? default;
            var keySecurity = Json.GetObject(element, "key_security");
            return new RegistrationState(
                Json.RequireString(element, "installation_id"),
                Json.RequireString(element, "device_id"),
                Json.RequireString(element, "key_thumbprint"),
                Json.GetString(element, "key_algorithm") ?? "unknown",
                Json.GetString(recognition, "method") ?? "unknown",
                Json.GetString(recognition, "confidence") ?? "unknown",
                Json.GetBoolean(recognition, "is_reinstall_correlation"),
                keySecurity is null ? null : KeySecurityState.Parse(keySecurity.Value),
                Json.GetBoolean(element, "stepup_key_registered"),
                Json.GetNullableBoolean(element, "stepup_key_matches"),
                Keys.StepUpKeyAuth.TryParse(Json.GetObject(element, "stepup_key_auth")),
                Json.GetNullableBoolean(element, "stepup_policy_downgrade"));
        }
    }

    /// <summary>The server's stored view of the installation key's protection.</summary>
    /// <remarks>
    /// Every field is nullable on purpose. Null means the client did not report
    /// it, and the server never collapses that to "software" (DESIGN.md 50).
    /// </remarks>
    public sealed class KeySecurityState
    {
        private KeySecurityState(string? securityLevel, bool? hardwareBacked, string? provider, bool downgradeReported)
        {
            SecurityLevel = securityLevel;
            HardwareBacked = hardwareBacked;
            Provider = provider;
            DowngradeReported = downgradeReported;
        }

        /// <summary>The stored security level, for example <c>strongbox</c>.</summary>
        public string? SecurityLevel { get; }

        /// <summary>The stored hardware-backing claim.</summary>
        public bool? HardwareBacked { get; }

        /// <summary>The stored provider name.</summary>
        public string? Provider { get; }

        /// <summary>
        /// True when this registration claimed weaker protection than the server
        /// already held for the same key; the server kept the stronger value.
        /// </summary>
        public bool DowngradeReported { get; }

        internal static KeySecurityState Parse(JsonElement element)
        {
            return new KeySecurityState(
                Json.GetString(element, "security_level"),
                Json.GetNullableBoolean(element, "hardware_backed"),
                Json.GetString(element, "provider"),
                Json.GetBoolean(element, "downgrade_reported"));
        }
    }
}
