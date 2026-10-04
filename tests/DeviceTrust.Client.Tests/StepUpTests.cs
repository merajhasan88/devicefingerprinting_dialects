using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DeviceTrust.Client.Internal;
using DeviceTrust.Client.Keys;
using DeviceTrust.Client.Protocol;
using DeviceTrust.Client.Storage;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// The client half of DESIGN.md 50-58: key_security at registration, the
    /// optional step-up key, step-up proofs bound to the access-proof nonce, dead
    /// keys, and re-enrolment. The server contract is proven by the live
    /// conformance run; these pin the bytes this client puts on the wire.
    /// </summary>
    public sealed class StepUpTests : IDisposable
    {
        private readonly string _directory = Path.Combine(
            Path.GetTempPath(), "devicetrust-stepup-tests-" + Guid.NewGuid().ToString("N"));

        private readonly InMemoryInstallationStateStore _state = new InMemoryInstallationStateStore();

        public void Dispose()
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }

        [Theory]
        [InlineData("passcode", "per_use", 0, true)]
        [InlineData("biometric", "per_use", 0, true)]
        [InlineData("passcode", "windowed", 30, true)]
        [InlineData("passcode", "windowed", 3600, true)]
        [InlineData("passcode", "per_use", 30, false)]
        [InlineData("passcode", "windowed", 0, false)]
        [InlineData("passcode", "windowed", 3601, false)]
        [InlineData("face", "per_use", 0, false)]
        [InlineData("passcode", "sometimes", 0, false)]
        public void StepUpKeyAuth_AcceptsExactlyWhatTheServerAccepts(string factor, string mode, int window, bool valid)
        {
            if (valid)
            {
                Assert.Equal(window, new StepUpKeyAuth(factor, mode, window).WindowSeconds);
            }
            else
            {
                Assert.Throws<ArgumentException>(() => new StepUpKeyAuth(factor, mode, window));
            }
        }

        [Fact]
        public async Task Register_SendsKeySecurityAndTheStepUpKey()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true));
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);

            var registration = await client.RegisterInstallationAsync();

            var body = server.Requests.Single().Json;
            var keySecurity = body.GetProperty("key_security");
            Assert.Equal("software", keySecurity.GetProperty("security_level").GetString());
            Assert.Equal(JsonValueKind.False, keySecurity.GetProperty("hardware_backed").ValueKind);
            Assert.Equal("software-file", keySecurity.GetProperty("provider").GetString());

            var jwk = body.GetProperty("stepup_public_key");
            Assert.Equal(client.StepUpKey!.PublicKey.X, jwk.GetProperty("x").GetString());
            Assert.Equal("ES256", jwk.GetProperty("alg").GetString());
            var auth = body.GetProperty("stepup_key_auth");
            Assert.Equal("passcode", auth.GetProperty("factor").GetString());
            Assert.Equal("per_use", auth.GetProperty("mode").GetString());
            Assert.Equal(0, auth.GetProperty("window_seconds").GetInt32());

            Assert.True(registration.StepUpKeyRegistered);
            Assert.True(client.StepUpUsable);
        }

        [Fact]
        public void KeySecurity_AnUnknownLevelIsSentAsNullNotAsSoftware()
        {
            // "unknown" with hardware_backed false would be a claim of software
            // backing on no evidence, which an advisory server scores +30.
            var metadata = new InstallationKeyMetadata(
                new EcPublicJsonWebKey(new byte[32], new byte[32]),
                "alias", "AndroidKeyStore", "unknown", false, false, false);

            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                DeviceTrustApi.WriteKeySecurity(writer, metadata);
            }

            using var document = JsonDocument.Parse(buffer.ToArray());
            Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("security_level").ValueKind);
            Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("hardware_backed").ValueKind);
            Assert.Equal("AndroidKeyStore", document.RootElement.GetProperty("provider").GetString());
        }

        [Fact]
        public async Task Register_NoScreenLockStillEnrolsWithoutAStepUpKey()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: false));
            using var client = CreateClient(server, new UnavailableStepUpKeyStore());

            var registration = await client.RegisterInstallationAsync();

            var body = server.Requests.Single().Json;
            Assert.False(body.TryGetProperty("stepup_public_key", out _));
            Assert.False(body.TryGetProperty("stepup_key_auth", out _));
            Assert.Equal(StepUpErrorCodes.NoDeviceCredential, client.StepUpUnavailable!.Code);
            Assert.False(registration.StepUpKeyRegistered);
            Assert.False(client.StepUpUsable);
        }

        [Fact]
        public async Task StepUp_ProofIsSignedByTheStepUpKeyAndBoundToTheAccessProofNonce()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true));
            server.Respond("{\"step_up\":\"verified\"}");
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);
            await client.RegisterInstallationAsync();
            await SignInAsync(client);

            await client.SensitiveEchoAsync(
                new Dictionary<string, object?>(StringComparer.Ordinal) { ["operation"] = "transfer" },
                withStepUp: true);

            var request = server.Requests.Last();
            Assert.Equal("/v1/account/sensitive-echo", request.Path);
            var proofBytes = Base64Url.Decode(request.Headers["X-Step-Up-Proof"]);
            var signature = Base64Url.Decode(request.Headers["X-Step-Up-Signature"]);
            var accessProof = JsonDocument.Parse(Base64Url.Decode(request.Headers["X-Access-Proof"])).RootElement;

            using var proofDocument = JsonDocument.Parse(proofBytes);
            var proof = proofDocument.RootElement;
            Assert.Equal(2, proof.GetProperty("version").GetInt32());
            Assert.Equal("stepup", proof.GetProperty("purpose").GetString());
            Assert.Equal(client.Identity!.InstallationId, proof.GetProperty("installation_id").GetString());
            Assert.Equal("passcode", proof.GetProperty("factor").GetString());
            Assert.Equal(JsonValueKind.Number, proof.GetProperty("timestamp").ValueKind);

            // Version 2 approves this exact request: every field the server
            // compares equals what the access proof signed and what was sent.
            Assert.Equal(Hex.Sha256Hex("access-token"), proof.GetProperty("access_token_sha256").GetString());
            Assert.Equal("POST", proof.GetProperty("method").GetString());
            Assert.Equal("/v1/account/sensitive-echo", proof.GetProperty("path").GetString());
            Assert.Equal(string.Empty, proof.GetProperty("query").GetString());
            Assert.Equal(Hex.Sha256Hex(request.Body), proof.GetProperty("body_sha256").GetString());
            foreach (var field in new[] { "nonce", "access_token_sha256", "method", "path", "query", "body_sha256" })
            {
                Assert.Equal(accessProof.GetProperty(field).GetString(), proof.GetProperty(field).GetString());
            }

            Assert.True(EcdsaSignatureFormat.LooksLikeDerSequence(signature));
            using var stepUpPublic = PublicKey(client.StepUpKey!.PublicKey);
            Assert.True(EcdsaSignatureFormat.VerifyDer(stepUpPublic, proofBytes, signature));

            // And not by the installation key: that one signs unattended, which is
            // the whole reason a second key exists.
            using var installationPublic = PublicKey(client.Identity.Key.PublicKey);
            Assert.False(EcdsaSignatureFormat.VerifyDer(installationPublic, proofBytes, signature));
        }

        [Fact]
        public async Task StepUp_WithoutStepUpSendsNoStepUpHeaders()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true));
            server.Respond("{\"step_up\":\"not_required\"}");
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);
            await client.RegisterInstallationAsync();
            await SignInAsync(client);

            await client.SensitiveEchoAsync(new Dictionary<string, object?>(), withStepUp: false);

            Assert.False(server.Requests.Last().Headers.ContainsKey("X-Step-Up-Proof"));
        }

        [Fact]
        public async Task StepUp_ADeadKeyIsDroppedAndReportedAsInvalidated()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true));
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);
            await client.RegisterInstallationAsync();
            await SignInAsync(client);
            stepUp.SimulateInvalidation();

            var error = await Assert.ThrowsAsync<InstallationKeyException>(() =>
                client.SensitiveEchoAsync(new Dictionary<string, object?>(), withStepUp: true));

            Assert.Equal(StepUpErrorCodes.KeyInvalidated, error.Code);
            Assert.Null(client.StepUpKey);
            Assert.False(client.StepUpUsable);
            Assert.Single(server.Requests); // nothing was sent for the sensitive call
        }

        [Fact]
        public async Task Reenrol_ProvesTheNewKeyOverItsThumbprintAndTheRequestNonce()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: false));
            server.Respond("{\"stepup_key_registered\":true,\"stepup_key_auth\":"
                           + "{\"factor\":\"passcode\",\"mode\":\"per_use\",\"window_seconds\":0},"
                           + "\"stepup_policy_downgrade\":false}");
            server.Respond(RegistrationResponse(stepUpRegistered: true, matches: true));
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);
            await client.RegisterInstallationAsync();
            await SignInAsync(client);
            Assert.False(client.StepUpUsable);

            await client.ReenrolStepUpKeyAsync("Passw0rd123");

            var request = server.Requests[1];
            Assert.Equal("/v1/installations/stepup-key", request.Path);
            var body = request.Json;
            Assert.Equal("Passw0rd123", body.GetProperty("password").GetString());
            Assert.Equal(client.StepUpKey!.PublicKey.X, body.GetProperty("stepup_public_key").GetProperty("x").GetString());
            Assert.Equal("per_use", body.GetProperty("stepup_key_auth").GetProperty("mode").GetString());

            var keyProofBytes = Base64Url.Decode(body.GetProperty("stepup_key_proof").GetString()!);
            using var keyProofDocument = JsonDocument.Parse(keyProofBytes);
            var keyProof = keyProofDocument.RootElement;
            var accessProof = JsonDocument.Parse(Base64Url.Decode(request.Headers["X-Access-Proof"])).RootElement;
            Assert.Equal("stepup_reenrol", keyProof.GetProperty("purpose").GetString());
            Assert.Equal(client.StepUpKey.Thumbprint, keyProof.GetProperty("stepup_key_thumbprint").GetString());
            Assert.Equal(accessProof.GetProperty("nonce").GetString(), keyProof.GetProperty("nonce").GetString());
            Assert.Equal(client.Identity!.InstallationId, keyProof.GetProperty("installation_id").GetString());

            using var stepUpPublic = PublicKey(client.StepUpKey.PublicKey);
            Assert.True(EcdsaSignatureFormat.VerifyDer(
                stepUpPublic,
                keyProofBytes,
                Base64Url.Decode(body.GetProperty("stepup_key_signature").GetString()!)));

            // Re-registered afterwards, so the server's view is what the caller sees.
            Assert.Equal("/v1/installations/register", server.Requests[2].Path);
            Assert.True(client.StepUpUsable);
        }

        [Fact]
        public async Task ANewInstallationKeyRotatesTheStepUpKey()
        {
            var server = new ScriptedServer();
            using var stepUp = new SoftwareStepUpKeyStore(true);
            var first = await stepUp.GetOrCreateKeyAsync(StepUpKeyAuth.PasscodePerUse);
            using var client = CreateClient(server, stepUp);

            await client.LoadIdentityAsync(); // creates the installation key

            var second = await stepUp.GetOrCreateKeyAsync(StepUpKeyAuth.PasscodePerUse);
            Assert.True(second.Created);
            Assert.NotEqual(first.Thumbprint, second.Thumbprint);
        }

        [Fact]
        public async Task StepUp_BothProofsSignTheQueryTheRequestCarries()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true));
            server.Respond("{\"step_up\":\"verified\"}");
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);
            await client.RegisterInstallationAsync();
            await SignInAsync(client);

            await client.SendStepUpProtectedAsync(
                "POST",
                "/v1/account/sensitive-echo?to=me&note=a b",
                Encoding.UTF8.GetBytes("{\"x\":1}"),
                "access-token",
                "test");

            var request = server.Requests.Last();
            var sentQuery = request.Query.TrimStart('?');
            Assert.Equal("to=me&note=a%20b", sentQuery);
            var accessProof = JsonDocument.Parse(Base64Url.Decode(request.Headers["X-Access-Proof"])).RootElement;
            var stepUpProof = JsonDocument.Parse(Base64Url.Decode(request.Headers["X-Step-Up-Proof"])).RootElement;
            Assert.Equal(2, accessProof.GetProperty("version").GetInt32());
            Assert.Equal("/v1/account/sensitive-echo", accessProof.GetProperty("path").GetString());
            Assert.Equal(sentQuery, accessProof.GetProperty("query").GetString());
            Assert.Equal(sentQuery, stepUpProof.GetProperty("query").GetString());
            Assert.Equal("/v1/account/sensitive-echo", stepUpProof.GetProperty("path").GetString());
        }

        [Fact]
        public async Task StepUp_ARefusedReenrolmentLeavesTheFreshKeyUnusable()
        {
            // DESIGN.md 63.10, found on the reference iPhone. The passcode is off
            // at launch, so no key is offered and the server answers with its
            // (dead) bound key: registered=true, matches=null. With the passcode
            // back, a re-enrolment with the wrong password creates a fresh key and
            // is refused. A rule that excludes only matches=false would now offer
            // that unbound key; the server would refuse its signature.
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true, matches: null));
            server.Respond("{\"error\":{\"code\":\"invalid_credentials\",\"message\":\"no\"}}",
                HttpStatusCode.Unauthorized);
            var stepUp = new SwitchableStepUpKeyStore { Unavailable = true };
            using var client = CreateClient(server, stepUp);

            await client.RegisterInstallationAsync();
            Assert.Null(client.StepUpKey);
            Assert.Null(client.BoundStepUpThumbprint);

            stepUp.Unavailable = false;
            await SignInAsync(client);
            var refused = await Assert.ThrowsAsync<DeviceTrustApiException>(
                () => client.ReenrolStepUpKeyAsync("wrong-password"));

            Assert.Equal("invalid_credentials", refused.Code);
            Assert.NotNull(client.StepUpKey);
            Assert.True(client.Registration!.StepUpKeyRegistered);
            Assert.Null(client.Registration.StepUpKeyMatches);
            Assert.False(client.StepUpUsable);
        }

        [Fact]
        public async Task StepUp_AKeyReportedAsDifferentIsNotUsable()
        {
            var server = new ScriptedServer();
            server.Respond(RegistrationResponse(stepUpRegistered: true, matches: false));
            using var stepUp = new SoftwareStepUpKeyStore(true);
            using var client = CreateClient(server, stepUp);

            await client.RegisterInstallationAsync();

            Assert.NotNull(client.StepUpKey);
            Assert.Null(client.BoundStepUpThumbprint);
            Assert.False(client.StepUpUsable);
        }

        [Fact]
        public async Task StepUp_TheOfferedKeyIsBoundOnANewInstallationOrWhenItMatches()
        {
            foreach (var matches in new bool?[] { null, true })
            {
                var server = new ScriptedServer();
                server.Respond(RegistrationResponse(stepUpRegistered: true, matches: matches));
                using var stepUp = new SoftwareStepUpKeyStore(true);
                using var client = CreateClient(server, stepUp);

                await client.RegisterInstallationAsync();

                Assert.Equal(client.StepUpKey!.Thumbprint, client.BoundStepUpThumbprint);
                Assert.True(client.StepUpUsable);
            }
        }

        [Fact]
        public void Options_RefusePlainHttpUnlessAllowed()
        {
            var options = new DeviceTrustOptions { BaseUrl = "http://lab.test:5000" };
            Assert.Equal("api_base_url_insecure",
                Assert.Throws<DeviceTrustConfigurationException>(() => options.ResolveBaseUri()).Code);

            options.AllowInsecureHttp = true;
            Assert.Equal("http", options.ResolveBaseUri().Scheme);
        }

        [Fact]
        public void RegistrationState_KeepsNullMatchesDistinctFromFalse()
        {
            using var document = JsonDocument.Parse(RegistrationResponse(stepUpRegistered: true, matches: false));
            var mismatched = RegistrationState.Parse(document.RootElement);
            Assert.False(mismatched.StepUpKeyMatches);
            Assert.Equal(StepUpKeyAuth.PasscodePerUse, mismatched.StepUpKeyAuth);
            Assert.True(mismatched.KeySecurity!.HardwareBacked);

            using var plain = JsonDocument.Parse(
                "{\"installation_id\":\"i\",\"device_id\":\"d\",\"key_thumbprint\":\"t\"}");
            var old = RegistrationState.Parse(plain.RootElement);
            Assert.Null(old.StepUpKeyMatches);
            Assert.Null(old.StepUpKeyAuth);
            Assert.Null(old.KeySecurity);
            Assert.False(old.StepUpKeyRegistered);
        }

        private DeviceTrustClient CreateClient(ScriptedServer server, IStepUpKeyStore stepUp)
        {
            var keyStore = new SoftwareInstallationKeyStore(
                Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".p8"),
                acknowledgeNotHardwareBacked: true);
            return new DeviceTrustClient(
                new DeviceTrustOptions { BaseUrl = "https://server.test", Platform = "android" },
                keyStore,
                _state,
                null,
                new HttpClient(server),
                stepUp);
        }

        private async Task SignInAsync(DeviceTrustClient client)
        {
            // A session as a previous run would have persisted it; the tests only
            // need the tokens to bind proofs to.
            var state = new InstallationState
            {
                InstallationId = client.Identity!.InstallationId,
                AccountId = "account-1",
                AccessToken = "access-token",
                RefreshToken = "refresh-token",
            };
            await _state.SaveAsync(state);
            Assert.NotNull(await client.RestoreSessionAsync());
        }

        private static string RegistrationResponse(bool stepUpRegistered, bool? matches = null)
        {
            var matchesJson = matches is null ? "null" : matches.Value ? "true" : "false";
            return "{\"installation_id\":\"6f1c2d3e-0000-4000-8000-000000000001\",\"device_id\":\"device-1\","
                   + "\"key_thumbprint\":\"t\",\"key_algorithm\":\"ES256\","
                   + "\"recognition\":{\"method\":\"new_device\",\"confidence\":\"new\",\"is_reinstall_correlation\":false},"
                   + "\"key_security\":{\"security_level\":\"strongbox\",\"hardware_backed\":true,\"provider\":\"AndroidKeyStore\"},"
                   + "\"stepup_key_registered\":" + (stepUpRegistered ? "true" : "false") + ","
                   + "\"stepup_key_matches\":" + matchesJson + ","
                   + "\"stepup_key_auth\":" + (stepUpRegistered
                       ? "{\"factor\":\"passcode\",\"mode\":\"per_use\",\"window_seconds\":0}"
                       : "null") + ","
                   + "\"stepup_policy_downgrade\":" + (stepUpRegistered ? "false" : "null") + "}";
        }

        private static ECDsa PublicKey(EcPublicJsonWebKey jwk)
        {
            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64Url.Decode(jwk.X), Y = Base64Url.Decode(jwk.Y) },
            });
        }

        private sealed class UnavailableStepUpKeyStore : IStepUpKeyStore
        {
            public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(
                StepUpKeyAuth requested,
                CancellationToken cancellationToken = default)
            {
                throw new InstallationKeyException(
                    StepUpErrorCodes.NoDeviceCredential,
                    "Set a screen lock (PIN, pattern or password) to enable step-up.");
            }

            public Task<byte[]> SignAsync(byte[] data, string reason, CancellationToken cancellationToken = default)
            {
                throw new InvalidOperationException("no key");
            }

            public Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default)
            {
                return Task.FromResult(false);
            }
        }

        /// <summary>A software step-up store whose screen lock can be switched off.</summary>
        private sealed class SwitchableStepUpKeyStore : IStepUpKeyStore
        {
            private readonly SoftwareStepUpKeyStore _inner = new SoftwareStepUpKeyStore(true);

            public bool Unavailable { get; set; }

            public Task<StepUpKeyMetadata> GetOrCreateKeyAsync(
                StepUpKeyAuth requested,
                CancellationToken cancellationToken = default)
            {
                return Unavailable
                    ? throw new InstallationKeyException(StepUpErrorCodes.NoDeviceCredential, "no passcode")
                    : _inner.GetOrCreateKeyAsync(requested, cancellationToken);
            }

            public Task<byte[]> SignAsync(byte[] data, string reason, CancellationToken cancellationToken = default)
            {
                return _inner.SignAsync(data, reason, cancellationToken);
            }

            public Task<bool> DeleteKeyAsync(CancellationToken cancellationToken = default)
            {
                return _inner.DeleteKeyAsync(cancellationToken);
            }
        }

        private sealed class ScriptedServer : HttpMessageHandler
        {
            private readonly Queue<(string Json, HttpStatusCode Status)> _responses =
                new Queue<(string Json, HttpStatusCode Status)>();

            public List<RecordedRequest> Requests { get; } = new List<RecordedRequest>();

            public void Respond(string json, HttpStatusCode status = HttpStatusCode.OK) =>
                _responses.Enqueue((json, status));

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                var body = request.Content is null
                    ? Array.Empty<byte>()
                    : await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var headers = request.Headers.ToDictionary(
                    header => header.Key,
                    header => string.Join(",", header.Value),
                    StringComparer.OrdinalIgnoreCase);
                Requests.Add(new RecordedRequest(request.RequestUri!.AbsolutePath, request.RequestUri.Query, headers, body));

                if (_responses.Count == 0)
                {
                    throw new InvalidOperationException("Unexpected request to " + request.RequestUri);
                }

                var (json, status) = _responses.Dequeue();
                return new HttpResponseMessage(status)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
            }
        }

        private sealed class RecordedRequest
        {
            public RecordedRequest(string path, string query, Dictionary<string, string> headers, byte[] body)
            {
                Path = path;
                Query = query;
                Headers = headers;
                Body = body;
            }

            public string Path { get; }

            public string Query { get; }

            public Dictionary<string, string> Headers { get; }

            public byte[] Body { get; }

            public JsonElement Json => JsonDocument.Parse(Body).RootElement;
        }
    }
}
