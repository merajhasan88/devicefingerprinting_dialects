using System;

namespace DeviceTrust.Client.Protocol
{
    /// <summary>
    /// A signed access proof together with the request it describes, kept apart
    /// from the request that will actually be sent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Ordinary calls never need this type; <see cref="DeviceTrustClient"/> builds
    /// and sends a proof in one step. It exists so the boundary tests can send a
    /// <i>correctly signed</i> proof alongside a <i>different</i> request — a
    /// replay, a tampered body, a mismatched path or method, an expired
    /// timestamp — which is the only way to prove that the server is checking
    /// each binding rather than merely checking the signature.
    /// </para>
    /// <para>
    /// It mirrors the Flutter client's <c>buildAccessProofFixture</c> /
    /// <c>sendAccessProofFixture</c> pair for exactly the same reason.
    /// </para>
    /// </remarks>
    public sealed class AccessProofFixture
    {
        /// <summary>Creates a fixture.</summary>
        public AccessProofFixture(
            string bearerToken,
            string signedMethod,
            string signedPath,
            byte[] encodedBody,
            string proofPayload,
            string signature,
            long timestamp,
            string nonce)
        {
            BearerToken = bearerToken ?? throw new ArgumentNullException(nameof(bearerToken));
            SignedMethod = signedMethod ?? throw new ArgumentNullException(nameof(signedMethod));
            SignedPath = signedPath ?? throw new ArgumentNullException(nameof(signedPath));
            EncodedBody = encodedBody ?? throw new ArgumentNullException(nameof(encodedBody));
            ProofPayload = proofPayload ?? throw new ArgumentNullException(nameof(proofPayload));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            Timestamp = timestamp;
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        /// <summary>The bearer token the proof is bound to.</summary>
        public string BearerToken { get; }

        /// <summary>The HTTP method named inside the signed proof.</summary>
        public string SignedMethod { get; }

        /// <summary>The path named inside the signed proof.</summary>
        public string SignedPath { get; }

        /// <summary>The exact body bytes whose SHA-256 is inside the signed proof.</summary>
        public byte[] EncodedBody { get; }

        /// <summary>The <c>X-Access-Proof</c> header value: base64url of the proof JSON.</summary>
        public string ProofPayload { get; }

        /// <summary>The <c>X-Access-Signature</c> header value: base64url of the DER signature.</summary>
        public string Signature { get; }

        /// <summary>The Unix-seconds timestamp inside the proof.</summary>
        public long Timestamp { get; }

        /// <summary>The single-use base64url nonce inside the proof.</summary>
        public string Nonce { get; }
    }
}
