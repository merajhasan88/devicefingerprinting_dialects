using System;
using System.Collections.Generic;

namespace DeviceTrust.Client.Integrity
{
    /// <summary>
    /// One probe's raw measurements.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A probe reports what it measured and nothing more. It never reports a
    /// risk score, a verdict or an opinion: the server owns scoring, and a
    /// client-supplied score would be the first thing an attacker forged.
    /// </para>
    /// <para>
    /// Every result carries a <c>status</c>. <c>ok</c> means the probe ran;
    /// <c>error</c> and <c>unsupported</c> mean it did not, and the server adds
    /// risk points for a server-requested probe that did not complete. Reporting
    /// <c>error</c> honestly is therefore the correct behaviour — filling in a
    /// plausible clean-looking value to avoid the penalty is the one thing a
    /// collector must never do.
    /// </para>
    /// </remarks>
    public sealed class ProbeResult
    {
        private readonly Dictionary<string, object?> _fields = new Dictionary<string, object?>(StringComparer.Ordinal);

        private ProbeResult(string status)
        {
            _fields["status"] = status;
        }

        /// <summary>The probe's status: <c>ok</c>, <c>error</c> or <c>unsupported</c>.</summary>
        public string Status => (string)_fields["status"]!;

        /// <summary>The measurement fields, including <c>status</c>.</summary>
        public IReadOnlyDictionary<string, object?> Fields => _fields;

        /// <summary>Starts a successful probe result.</summary>
        public static ProbeResult Ok()
        {
            return new ProbeResult("ok");
        }

        /// <summary>Reports that the probe threw or could not read what it needed.</summary>
        public static ProbeResult Error(string errorType, string message)
        {
            var result = new ProbeResult("error");
            result._fields["error_type"] = errorType;
            result._fields["error"] = Truncate(message, 240);
            return result;
        }

        /// <summary>Reports that this platform cannot run the requested probe at all.</summary>
        public static ProbeResult Unsupported(string reason)
        {
            var result = new ProbeResult("unsupported");
            result._fields["reason"] = Truncate(reason, 240);
            return result;
        }

        /// <summary>Adds a measurement field, ignoring nulls as the Kotlin collector does.</summary>
        public ProbeResult With(string name, object? value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A field name is required.", nameof(name));
            }

            if (value is not null)
            {
                _fields[name] = value;
            }

            return this;
        }

        private static string Truncate(string value, int maximum)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value.Length <= maximum ? value : value.Substring(0, maximum);
        }
    }
}
