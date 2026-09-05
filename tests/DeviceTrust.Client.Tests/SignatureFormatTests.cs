using System;
using System.Security.Cryptography;
using System.Text;
using DeviceTrust.Client.Keys;
using Xunit;

namespace DeviceTrust.Client.Tests
{
    /// <summary>
    /// Guards the single .NET-specific defect that would break every request.
    /// </summary>
    /// <remarks>
    /// A naive .NET port signs with <c>ECDsa.SignData(data, HashAlgorithmName.SHA256)</c>,
    /// which returns IEEE P-1363 <c>r || s</c>. The server verifies ASN.1 DER, so
    /// every call fails with <c>401 invalid_installation_signature</c> — a code
    /// that reads like a stolen token, not like an encoding bug. These tests fail
    /// offline and immediately if that regression is ever reintroduced.
    /// </remarks>
    public sealed class SignatureFormatTests
    {
        private static readonly byte[] Payload = Encoding.UTF8.GetBytes("device trust signature encoding");

        [Fact]
        public void SignDer_ProducesAnAsn1DerSequence()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var signature = EcdsaSignatureFormat.SignDer(key, Payload);

            Assert.Equal(0x30, signature[0]);
            Assert.True(EcdsaSignatureFormat.LooksLikeDerSequence(signature));
        }

        [Fact]
        public void SignDer_DiffersFromTheDefaultOverload()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var der = EcdsaSignatureFormat.SignDer(key, Payload);
            var p1363 = key.SignData(Payload, HashAlgorithmName.SHA256);

            // P-256 P-1363 signatures are always exactly 64 bytes; DER ones are
            // 70-72 in practice and never a bare 64-byte blob.
            Assert.Equal(64, p1363.Length);
            Assert.NotEqual(64, der.Length);
        }

        [Fact]
        public void LooksLikeDerSequence_RejectsAP1363Signature()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var p1363 = key.SignData(Payload, HashAlgorithmName.SHA256);

            Assert.False(EcdsaSignatureFormat.LooksLikeDerSequence(p1363));
        }

        [Fact]
        public void VerifyDer_AcceptsWhatSignDerProduced()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var signature = EcdsaSignatureFormat.SignDer(key, Payload);

            Assert.True(EcdsaSignatureFormat.VerifyDer(key, Payload, signature));
        }

        [Fact]
        public void VerifyDer_RejectsASignatureOverDifferentBytes()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var signature = EcdsaSignatureFormat.SignDer(key, Payload);

            Assert.False(EcdsaSignatureFormat.VerifyDer(key, Encoding.UTF8.GetBytes("other bytes"), signature));
        }

        [Fact]
        public void VerifyDer_RejectsAnotherKeysSignature()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var signature = EcdsaSignatureFormat.SignDer(signer, Payload);

            Assert.False(EcdsaSignatureFormat.VerifyDer(other, Payload, signature));
        }
    }
}
