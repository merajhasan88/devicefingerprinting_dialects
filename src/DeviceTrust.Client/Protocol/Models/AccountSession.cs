using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>
    /// An account access/refresh token pair bound to this device and installation.
    /// </summary>
    /// <remarks>
    /// Both tokens carry <c>did</c> and <c>iid</c> claims, and neither is usable
    /// without a signature from this installation's key: the access token needs
    /// a per-request access proof, and the refresh token needs a signed refresh
    /// challenge. Copying the pair to another device therefore yields nothing.
    /// </remarks>
    public sealed class AccountSession
    {
        /// <summary>Creates an account session.</summary>
        public AccountSession(
            string accountId,
            string accessToken,
            string refreshToken,
            RiskPolicyDecision? policy)
        {
            AccountId = accountId;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            Policy = policy;
        }

        /// <summary>The account this session belongs to.</summary>
        public string AccountId { get; }

        /// <summary>The 10-minute access token.</summary>
        public string AccessToken { get; }

        /// <summary>The 30-day rotating refresh token.</summary>
        public string RefreshToken { get; }

        /// <summary>The relationship-risk decision returned alongside the tokens, when present.</summary>
        public RiskPolicyDecision? Policy { get; }

        /// <summary>Parses a token-issuing response.</summary>
        public static AccountSession Parse(JsonElement element)
        {
            var policy = Json.GetObject(element, "policy");
            return new AccountSession(
                Json.RequireString(element, "account_id"),
                Json.RequireString(element, "access_token"),
                Json.RequireString(element, "refresh_token"),
                policy is null ? null : RiskPolicyDecision.Parse(policy.Value));
        }
    }
}
