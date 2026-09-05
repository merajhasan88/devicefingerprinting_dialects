using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>
    /// The HTTP transport and the raw endpoint surface of the device-trust API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This type is deliberately thin. It owns byte-exact request bodies, the
    /// error envelope and the endpoint shapes, and nothing else; proof building,
    /// state and orchestration live in <see cref="DeviceTrustClient"/>. Keeping
    /// them apart is what lets the boundary tests send a body that does not match
    /// the proof that was signed for it.
    /// </para>
    /// <para>
    /// Bodies are sent as pre-serialised <see cref="byte"/> arrays rather than as
    /// objects, because the access proof commits to the SHA-256 of the exact
    /// bytes on the wire. Anything that could re-serialise between hashing and
    /// sending — a different encoder, a BOM, a re-ordered property — would
    /// produce <c>access_proof_body_mismatch</c> for reasons invisible in the
    /// source.
    /// </para>
    /// </remarks>
    public sealed class DeviceTrustApi : IDisposable
    {
        /// <summary>The header carrying the base64url proof JSON.</summary>
        public const string AccessProofHeader = "X-Access-Proof";

        /// <summary>The header carrying the base64url DER signature over the proof bytes.</summary>
        public const string AccessSignatureHeader = "X-Access-Signature";

        private static readonly MediaTypeHeaderValue JsonContentType = new MediaTypeHeaderValue("application/json");

        private readonly HttpClient _httpClient;
        private readonly bool _ownsHttpClient;
        private readonly TimeSpan _timeout;

        /// <summary>Creates an API client for the endpoint in <paramref name="options"/>.</summary>
        public DeviceTrustApi(DeviceTrustOptions options, HttpClient? httpClient = null)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            BaseUri = options.ResolveBaseUri();
            _timeout = options.NetworkTimeout;
            _ownsHttpClient = httpClient is null;
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <summary>The configured endpoint, with any trailing slash removed.</summary>
        public Uri BaseUri { get; }

        /// <summary>
        /// The path the access proof must name for a given API path.
        /// </summary>
        /// <remarks>
        /// The server compares the proof's <c>path</c> against its own
        /// <c>request.path</c>. When the service is deployed under a path prefix
        /// — behind a reverse proxy that does not strip it — that prefix is part
        /// of <c>request.path</c>, so it has to be part of the signed value too.
        /// </remarks>
        public string ResolveSignedPath(string path)
        {
            if (string.IsNullOrEmpty(path) || path[0] != '/')
            {
                throw new ArgumentException("An API path must start with '/'.", nameof(path));
            }

            var prefix = BaseUri.AbsolutePath.TrimEnd('/');
            return prefix.Length == 0 ? path : prefix + path;
        }

        /// <summary>Sends a request and returns the parsed JSON body, throwing on any non-2xx status.</summary>
        public async Task<JsonElement> SendAsync(
            string method,
            string path,
            byte[]? body = null,
            string? bearerToken = null,
            IReadOnlyDictionary<string, string>? extraHeaders = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(method))
            {
                throw new ArgumentException("An HTTP method is required.", nameof(method));
            }

            var normalizedMethod = method.ToUpperInvariant();
            using var request = new HttpRequestMessage(
                new HttpMethod(normalizedMethod),
                new Uri(BaseUri.AbsoluteUri.TrimEnd('/') + path));

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrEmpty(bearerToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            }

            if (extraHeaders is not null)
            {
                foreach (var header in extraHeaders)
                {
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            if (normalizedMethod != "GET" && body is not null)
            {
                var content = new ByteArrayContent(body);
                content.Headers.ContentType = JsonContentType;
                request.Content = content;
            }

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(_timeout);

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.SendAsync(request, timeoutSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new DeviceTrustApiException(
                    "The server did not respond before the " + _timeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)
                    + " second timeout.",
                    0,
                    "network_timeout");
            }
            catch (HttpRequestException error)
            {
                throw new DeviceTrustApiException(
                    "The connection to " + BaseUri + " failed: " + error.Message,
                    0,
                    "network_unreachable");
            }

            using (response)
            {
                var raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var status = (int)response.StatusCode;

                JsonElement parsed = default;
                var hasBody = !string.IsNullOrWhiteSpace(raw);
                if (hasBody)
                {
                    try
                    {
                        using var document = JsonDocument.Parse(raw);
                        parsed = document.RootElement.Clone();
                    }
                    catch (JsonException)
                    {
                        throw new DeviceTrustApiException(
                            "The server returned a non-JSON response.",
                            status,
                            "non_json_response");
                    }
                }

                if (status is < 200 or >= 300)
                {
                    throw BuildApiException(status, parsed, hasBody);
                }

                return parsed;
            }
        }

        /// <summary>Reads <c>GET /health/ready</c>.</summary>
        public Task<JsonElement> HealthReadyAsync(CancellationToken cancellationToken = default)
        {
            return SendAsync("GET", "/health/ready", cancellationToken: cancellationToken);
        }

        /// <summary>Registers an installation's public key.</summary>
        public async Task<RegistrationState> RegisterInstallationAsync(
            string installationId,
            string platform,
            EcPublicJsonWebKey publicKey,
            ReinstallHint? reinstallHint,
            CancellationToken cancellationToken = default)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("installation_id", installationId);
                writer.WriteString("platform", platform);
                writer.WritePropertyName("public_key");
                publicKey.Write(writer);
                writer.WritePropertyName("reinstall_hint");
                if (reinstallHint is null)
                {
                    writer.WriteNullValue();
                }
                else
                {
                    reinstallHint.Write(writer);
                }

                writer.WriteEndObject();
            }

            var response = await SendAsync(
                "POST",
                "/v1/installations/register",
                buffer.ToArray(),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return RegistrationState.Parse(response);
        }

        /// <summary>Requests an installation challenge to prove key possession.</summary>
        public Task<JsonElement> CreateInstallationChallengeAsync(
            string installationId,
            CancellationToken cancellationToken = default)
        {
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["installation_id"] = installationId,
            });
            return SendAsync("POST", "/v1/installations/challenge", body, cancellationToken: cancellationToken);
        }

        /// <summary>Submits the signed installation challenge and receives a device token.</summary>
        public Task<JsonElement> VerifyInstallationAsync(
            string installationId,
            string challengeId,
            string payload,
            string signature,
            CancellationToken cancellationToken = default)
        {
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["installation_id"] = installationId,
                ["challenge_id"] = challengeId,
                ["payload"] = payload,
                ["signature"] = signature,
            });
            return SendAsync("POST", "/v1/installations/verify", body, cancellationToken: cancellationToken);
        }

        /// <summary>Requests a refresh challenge, authenticated by the refresh token itself.</summary>
        public Task<JsonElement> RefreshChallengeAsync(
            string refreshToken,
            CancellationToken cancellationToken = default)
        {
            return SendAsync(
                "POST",
                "/v1/auth/refresh/challenge",
                Array.Empty<byte>(),
                refreshToken,
                cancellationToken: cancellationToken);
        }

        /// <summary>Rotates the refresh session with a signed refresh challenge.</summary>
        public async Task<AccountSession> RefreshAsync(
            string refreshToken,
            string challengeId,
            string payload,
            string signature,
            CancellationToken cancellationToken = default)
        {
            var body = Json.SerializeToUtf8Bytes(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["challenge_id"] = challengeId,
                ["payload"] = payload,
                ["signature"] = signature,
            });
            var response = await SendAsync("POST", "/v1/auth/refresh", body, refreshToken, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            return AccountSession.Parse(response);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (_ownsHttpClient)
            {
                _httpClient.Dispose();
            }
        }

        private static DeviceTrustApiException BuildApiException(int status, JsonElement parsed, bool hasBody)
        {
            // The envelope is nested: {"error": {"code": ..., "message": ...,
            // "details": {...}}}. Reading a flat top-level "code" would silently
            // produce null for every rejection and break control flow that keys
            // on the code, so the nesting is not optional.
            var error = hasBody ? Json.GetObject(parsed, "error") : null;
            var message = error is null
                ? "The server rejected the request (HTTP "
                  + status.ToString(CultureInfo.InvariantCulture) + ")."
                : Json.GetString(error.Value, "message")
                  ?? "The server rejected the request (HTTP "
                     + status.ToString(CultureInfo.InvariantCulture) + ").";
            var code = error is null ? null : Json.GetString(error.Value, "code");
            var details = error is null ? null : Json.GetObject(error.Value, "details");

            return new DeviceTrustApiException(
                message,
                status,
                code,
                details is null ? null : Json.ToDictionary(details.Value));
        }
    }
}
