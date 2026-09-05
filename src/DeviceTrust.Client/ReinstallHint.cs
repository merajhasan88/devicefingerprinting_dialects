using System;
using System.Text;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client
{
    /// <summary>
    /// A salted, hashed platform identifier that lets the server correlate a
    /// reinstall back to the same physical device.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The hint is a supporting signal, never an identity. Cryptographic key
    /// possession is the identity; the hint only answers "is this probably the
    /// same handset as before?" after an app is uninstalled and reinstalled,
    /// which destroys the keystore entry and therefore the key. A registration
    /// correlated this way is recorded as <c>reinstall_hint</c> with
    /// <c>medium</c> confidence, not <c>exact_key</c> with <c>high</c>.
    /// </para>
    /// <para>
    /// The raw platform value never leaves the device: it is lower-cased,
    /// trimmed, prefixed with a domain-separating label and SHA-256 hashed, and
    /// only the digest is sent. A missing hint must never block registration —
    /// the device simply enrols as new.
    /// </para>
    /// </remarks>
    public sealed class ReinstallHint
    {
        /// <summary>The domain-separation prefix. Changing it invalidates every stored hint.</summary>
        public const string DomainSeparator = "device-recognition-hint-v1";

        /// <summary>Creates a hint from an already-computed digest.</summary>
        public ReinstallHint(string kind, string value)
        {
            Kind = kind ?? throw new ArgumentNullException(nameof(kind));
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>The hint kind, for example <c>android_id_sha256</c> or <c>idfv_sha256</c>.</summary>
        public string Kind { get; }

        /// <summary>The lowercase hex SHA-256 digest.</summary>
        public string Value { get; }

        /// <summary>
        /// Hashes a raw platform identifier into a hint, using the same
        /// normalisation and domain separation as the Flutter client so that the
        /// two SDKs correlate to the same device record.
        /// </summary>
        public static ReinstallHint? FromRawIdentifier(string kind, string sourceLabel, string? rawValue)
        {
            if (string.IsNullOrWhiteSpace(rawValue))
            {
                return null;
            }

            var normalized = rawValue!.Trim().ToLowerInvariant();
            var digest = Hex.Sha256Hex(
                Encoding.UTF8.GetBytes(DomainSeparator + "|" + sourceLabel + "|" + normalized));
            return new ReinstallHint(kind, digest);
        }

        /// <summary>Writes the hint into a registration body.</summary>
        public void Write(Utf8JsonWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteStartObject();
            writer.WriteString("kind", Kind);
            writer.WriteString("value", Value);
            writer.WriteEndObject();
        }
    }
}
