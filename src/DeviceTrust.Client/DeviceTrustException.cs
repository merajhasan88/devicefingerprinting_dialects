using System;
using System.Collections.Generic;
using System.Text.Json;

namespace DeviceTrust.Client
{
    /// <summary>Base type for every failure this SDK raises.</summary>
    public class DeviceTrustException : Exception
    {
        /// <summary>Creates an exception with a message and a stable machine-readable code.</summary>
        public DeviceTrustException(string message, string? code = null, Exception? innerException = null)
            : base(message, innerException)
        {
            Code = code;
        }

        /// <summary>A stable machine-readable code, suitable for control flow.</summary>
        public string? Code { get; }

        /// <inheritdoc />
        public override string ToString()
        {
            return Code is null ? Message : Message + " [" + Code + "]";
        }
    }

    /// <summary>
    /// The SDK was configured incorrectly. The canonical case is a missing base
    /// URL, which fails with <c>api_base_url_missing</c> exactly as the Flutter
    /// client does, so a build can never silently point at someone else's
    /// environment.
    /// </summary>
    public sealed class DeviceTrustConfigurationException : DeviceTrustException
    {
        /// <summary>Creates a configuration exception.</summary>
        public DeviceTrustConfigurationException(string message, string code)
            : base(message, code)
        {
        }
    }

    /// <summary>
    /// The server answered, but not with something this protocol version
    /// understands. Distinct from <see cref="DeviceTrustApiException"/>, which
    /// carries a deliberate server-side rejection.
    /// </summary>
    public sealed class DeviceTrustProtocolException : DeviceTrustException
    {
        /// <summary>Creates a protocol exception.</summary>
        public DeviceTrustProtocolException(string message, string? code = null, Exception? innerException = null)
            : base(message, code, innerException)
        {
        }
    }

    /// <summary>
    /// A non-2xx response from the server.
    /// </summary>
    /// <remarks>
    /// The server's error envelope is nested — <c>{"error": {"code": ...,
    /// "message": ..., "details": {...}}}</c> — and its code is read
    /// from <c>error.code</c>, never from a flat top-level <c>code</c>. Control
    /// flow in every client SDK keys on that nested code.
    /// </remarks>
    public sealed class DeviceTrustApiException : DeviceTrustException
    {
        /// <summary>Creates an API exception from a parsed error envelope.</summary>
        public DeviceTrustApiException(
            string message,
            int statusCode,
            string? code = null,
            IReadOnlyDictionary<string, JsonElement>? details = null)
            : base(message, code)
        {
            StatusCode = statusCode;
            Details = details ?? new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        }

        /// <summary>The HTTP status code the server returned.</summary>
        public int StatusCode { get; }

        /// <summary>The contents of <c>error.details</c>, which may carry a policy or integrity decision.</summary>
        public IReadOnlyDictionary<string, JsonElement> Details { get; }

        /// <inheritdoc />
        public override string ToString()
        {
            return Code is null
                ? Message + " (HTTP " + StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")"
                : Message + " [" + Code + "] (HTTP " + StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")";
        }
    }

    /// <summary>
    /// The platform key store could not create, use or delete the installation
    /// key. Mirrors the <c>PlatformException</c> surface of the Flutter client's
    /// <c>installation_key_v2</c> method channel.
    /// </summary>
    public sealed class InstallationKeyException : DeviceTrustException
    {
        /// <summary>Creates an installation-key exception.</summary>
        public InstallationKeyException(string code, string message, Exception? innerException = null)
            : base(message, code, innerException)
        {
        }
    }
}
