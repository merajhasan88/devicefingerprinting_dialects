using System;
using System.Globalization;
using System.Text.Json;
using DeviceTrust.Client.Internal;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// How a step-up key is protected: the device factor that unlocks it, and
    /// whether each signature needs its own authentication.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the <c>stepup_key_auth</c> block of DESIGN.md 53. A key store
    /// reports what its keystore actually <i>enforces</i>, read back from the
    /// key after creation, not what the application asked for: on Android 9/10
    /// a passcode cannot be bound to one signature, so a per-use request comes
    /// back as <c>windowed</c> with a 30-second hardware window, and the server
    /// records that as a policy downgrade rather than having it hidden.
    /// </para>
    /// <para>
    /// Like the installation key's security level, it is a client claim. There
    /// is no key attestation in this design, so the server records and compares
    /// it but cannot re-verify which factor fired.
    /// </para>
    /// </remarks>
    public sealed class StepUpKeyAuth : IEquatable<StepUpKeyAuth>
    {
        /// <summary>The device passcode (PIN, pattern or password). The default.</summary>
        public const string FactorPasscode = "passcode";

        /// <summary>A strong biometric.</summary>
        public const string FactorBiometric = "biometric";

        /// <summary>Every signature needs a fresh authentication.</summary>
        public const string ModePerUse = "per_use";

        /// <summary>One authentication opens a hardware-enforced window.</summary>
        public const string ModeWindowed = "windowed";

        /// <summary>The longest window the server accepts.</summary>
        public const int MaxWindowSeconds = 3600;

        /// <summary>
        /// The Android 9/10 fallback window: the shortest the hardware can
        /// enforce for a passcode key there (DESIGN.md 53.2).
        /// </summary>
        public const int LegacyWindowSeconds = 30;

        /// <summary>Creates and validates an auth description.</summary>
        public StepUpKeyAuth(string factor, string mode, int windowSeconds)
        {
            if (factor != FactorPasscode && factor != FactorBiometric)
            {
                throw new ArgumentException("factor must be passcode or biometric.", nameof(factor));
            }

            if (mode != ModePerUse && mode != ModeWindowed)
            {
                throw new ArgumentException("mode must be per_use or windowed.", nameof(mode));
            }

            if (mode == ModePerUse && windowSeconds != 0)
            {
                throw new ArgumentException("A per_use step-up key has window_seconds 0.", nameof(windowSeconds));
            }

            if (mode == ModeWindowed && (windowSeconds < 1 || windowSeconds > MaxWindowSeconds))
            {
                throw new ArgumentException(
                    "A windowed step-up key needs window_seconds between 1 and "
                    + MaxWindowSeconds.ToString(CultureInfo.InvariantCulture) + ".",
                    nameof(windowSeconds));
            }

            Factor = factor;
            Mode = mode;
            WindowSeconds = windowSeconds;
        }

        /// <summary>Passcode on every use: the strongest setting and the default.</summary>
        public static StepUpKeyAuth PasscodePerUse { get; } = new StepUpKeyAuth(FactorPasscode, ModePerUse, 0);

        /// <summary><c>passcode</c> or <c>biometric</c>.</summary>
        public string Factor { get; }

        /// <summary><c>per_use</c> or <c>windowed</c>.</summary>
        public string Mode { get; }

        /// <summary>0 for per-use; the hardware window otherwise.</summary>
        public int WindowSeconds { get; }

        /// <summary>A short human description, for logs and harness screens.</summary>
        public string Description => Mode == ModePerUse
            ? Factor + ", per-use"
            : Factor + ", " + WindowSeconds.ToString(CultureInfo.InvariantCulture) + "s hardware window";

        /// <summary>Writes the <c>stepup_key_auth</c> object.</summary>
        public void Write(Utf8JsonWriter writer)
        {
            if (writer is null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.WriteStartObject();
            writer.WriteString("factor", Factor);
            writer.WriteString("mode", Mode);
            writer.WriteNumber("window_seconds", WindowSeconds);
            writer.WriteEndObject();
        }

        /// <summary>
        /// Parses a server-echoed auth block, or returns null when it is absent,
        /// null or not a well-formed description.
        /// </summary>
        public static StepUpKeyAuth? TryParse(JsonElement? element)
        {
            if (element is null || element.Value.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var factor = Json.GetString(element.Value, "factor");
            var mode = Json.GetString(element.Value, "mode");
            if (factor is null || mode is null
                || !element.Value.TryGetProperty("window_seconds", out var window)
                || window.ValueKind != JsonValueKind.Number
                || !window.TryGetInt32(out var seconds))
            {
                return null;
            }

            try
            {
                return new StepUpKeyAuth(factor, mode, seconds);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <inheritdoc />
        public bool Equals(StepUpKeyAuth? other)
        {
            return other is not null
                   && Factor == other.Factor
                   && Mode == other.Mode
                   && WindowSeconds == other.WindowSeconds;
        }

        /// <inheritdoc />
        public override bool Equals(object? obj) => Equals(obj as StepUpKeyAuth);

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return (Factor, Mode, WindowSeconds).GetHashCode();
        }

        /// <inheritdoc />
        public override string ToString() => Description;
    }
}
