using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Client.Keys
{
    /// <summary>
    /// The device-bound installation key, behind one abstraction so each platform
    /// can plug in its own non-exportable store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the .NET analogue of the Flutter client's
    /// <c>installation_key_v2</c> method channel, and it has deliberately the
    /// same three operations: get-or-create returning a public JWK, sign
    /// returning a DER signature, and delete. The private key must never cross
    /// this boundary — only the public JWK and the signatures do.
    /// </para>
    /// <para>
    /// Implementations must not be interchangeable in their security claims. An
    /// AndroidKeyStore or Secure Enclave key is non-exportable hardware-held
    /// material; a Windows CNG key is protected by the OS or a TPM but is not
    /// the same thing; a software key in a file is neither, and exists only for
    /// protocol testing.
    /// </para>
    /// </remarks>
    public interface IInstallationKeyStore
    {
        /// <summary>
        /// Returns the existing installation key, creating one if the store holds
        /// none. <see cref="InstallationKeyMetadata.Created"/> reports which
        /// happened, because the caller must rotate the installation UUID when a
        /// new key appears.
        /// </summary>
        Task<InstallationKeyMetadata> GetOrCreateKeyAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Signs the exact bytes supplied and returns an <b>ASN.1 DER</b>
        /// ECDSA-SHA256 signature.
        /// </summary>
        /// <remarks>
        /// This is the single sharpest .NET-specific trap in the whole protocol.
        /// <c>ECDsa.SignData(byte[], HashAlgorithmName)</c> emits IEEE P-1363
        /// fixed-width <c>r || s</c>, which the server — PyCryptodome, DER —
        /// rejects with <c>invalid_installation_signature</c> on every single
        /// call. Implementations must use the
        /// <c>DSASignatureFormat.Rfc3279DerSequence</c> overload, or a platform
        /// API that already produces DER (Android's <c>SHA256withECDSA</c> and
        /// Apple's X9.62 signing both do).
        /// </remarks>
        Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);

        /// <summary>Deletes the installation key, if one exists.</summary>
        Task DeleteKeyAsync(CancellationToken cancellationToken = default);
    }
}
