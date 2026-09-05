using System;
using System.Security.Cryptography;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// The one correct way to sign and verify for this protocol, in one place.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every signature this protocol carries — installation challenge, refresh
    /// challenge, access proof and integrity report — is an ECDSA-SHA256
    /// signature in <b>ASN.1 DER</b> (an X9.62 <c>SEQUENCE { r, s }</c>). The
    /// server verifies with PyCryptodome's DER encoding, and the Android and
    /// Apple platform APIs produce DER natively.
    /// </para>
    /// <para>
    /// .NET does not. <c>ECDsa.SignData(data, HashAlgorithmName.SHA256)</c>
    /// returns IEEE P-1363 <c>r || s</c> — 64 fixed-width bytes with no
    /// structure — and a DER verifier rejects it every time. The failure is
    /// silent in the sense that it never looks like an encoding problem: the
    /// server answers <c>401 invalid_installation_signature</c>, which reads
    /// like a wrong-key or stolen-token result. Routing all signing through this
    /// class is what stops that from being rediscovered.
    /// </para>
    /// </remarks>
    public static class EcdsaSignatureFormat
    {
        /// <summary>Signs data with ECDSA-SHA256 and returns an ASN.1 DER signature.</summary>
        public static byte[] SignDer(ECDsa key, byte[] data)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }

        /// <summary>Verifies an ASN.1 DER ECDSA-SHA256 signature.</summary>
        public static bool VerifyDer(ECDsa key, byte[] data, byte[] signature)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            return key.VerifyData(
                data,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }

        /// <summary>
        /// Reports whether a signature is at least shaped like a DER SEQUENCE of
        /// two INTEGERs. Used by the test harness to catch the P-1363 mistake as
        /// an encoding problem rather than as an authentication failure.
        /// </summary>
        public static bool LooksLikeDerSequence(byte[] signature)
        {
            if (signature is null || signature.Length < 8 || signature[0] != 0x30)
            {
                return false;
            }

            int declaredLength = signature[1];
            var offset = 2;
            if (declaredLength > 0x80)
            {
                var lengthBytes = declaredLength - 0x80;
                if (lengthBytes < 1 || lengthBytes > 2 || signature.Length < 2 + lengthBytes)
                {
                    return false;
                }

                declaredLength = 0;
                for (var index = 0; index < lengthBytes; index++)
                {
                    declaredLength = (declaredLength << 8) | signature[2 + index];
                }

                offset = 2 + lengthBytes;
            }

            if (offset + declaredLength != signature.Length)
            {
                return false;
            }

            return signature[offset] == 0x02;
        }
    }
}
