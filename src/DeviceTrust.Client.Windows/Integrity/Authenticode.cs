using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace DeviceTrust.Client.Windows.Integrity
{
    /// <summary>The Authenticode state of one file on disk.</summary>
    public sealed class AuthenticodeStatus
    {
        internal AuthenticodeStatus(string state, string? subject, string? thumbprint)
        {
            State = state;
            Subject = subject;
            Thumbprint = thumbprint;
        }

        /// <summary>
        /// <c>valid</c>, <c>unsigned</c>, <c>untrusted</c>, <c>expired</c>,
        /// <c>revoked</c> or <c>unknown</c>.
        /// </summary>
        public string State { get; }

        /// <summary>The signer's subject name, when a signature was present.</summary>
        public string? Subject { get; }

        /// <summary>The signing certificate's SHA-1 thumbprint, when a signature was present.</summary>
        public string? Thumbprint { get; }
    }

    /// <summary>
    /// Verifies Authenticode signatures with <c>WinVerifyTrust</c>.
    /// </summary>
    /// <remarks>
    /// Reading the embedded certificate with
    /// <see cref="X509Certificate.CreateFromSignedFile(string)"/> alone would be a
    /// mistake worth naming: it extracts whatever certificate the file carries
    /// without verifying that the signature covers the file or that the chain is
    /// trusted, so a tampered or self-signed binary looks "signed". The chain
    /// verdict has to come from <c>WinVerifyTrust</c>; the certificate is read
    /// only to report who signed it.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    public static class Authenticode
    {
        private const int TrustEOk = 0;
        private const int TrustENosignature = unchecked((int)0x800B0100);
        private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
        private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
        private const int CertEUntrustedroot = unchecked((int)0x800B0109);
        private const int CertEExpired = unchecked((int)0x800B0101);
        private const int CertERevoked = unchecked((int)0x800B010C);
        private const int CertEChaining = unchecked((int)0x800B010A);

        /// <summary>Verifies a file and reports the signer.</summary>
        public static AuthenticodeStatus Verify(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                throw new ArgumentException("A file path is required.", nameof(filePath));
            }

            var state = VerifyChain(filePath);
            string? subject = null;
            string? thumbprint = null;

            if (state != "unsigned")
            {
                try
                {
                    using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
                    subject = certificate.Subject;
                    thumbprint = certificate.Thumbprint;
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    // The chain verdict above is the authoritative answer; the
                    // signer name is descriptive only.
                }
            }

            return new AuthenticodeStatus(state, subject, thumbprint);
        }

        private static string VerifyChain(string filePath)
        {
            var pathPointer = Marshal.StringToHGlobalUni(filePath);
            var fileInfoPointer = IntPtr.Zero;
            var dataPointer = IntPtr.Zero;

            try
            {
                var fileInfo = new NativeMethods.WinTrustFileInfo
                {
                    StructSize = (uint)Marshal.SizeOf<NativeMethods.WinTrustFileInfo>(),
                    FilePath = pathPointer,
                    FileHandle = IntPtr.Zero,
                    KnownSubject = IntPtr.Zero,
                };
                fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WinTrustFileInfo>());
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

                var data = new NativeMethods.WinTrustData
                {
                    StructSize = (uint)Marshal.SizeOf<NativeMethods.WinTrustData>(),
                    UiChoice = NativeMethods.WtdUiNone,
                    RevocationChecks = NativeMethods.WtdRevokeNone,
                    UnionChoice = NativeMethods.WtdChoiceFile,
                    FileInfoPtr = fileInfoPointer,
                    StateAction = NativeMethods.WtdStateActionVerify,
                    ProviderFlags = NativeMethods.WtdSaferFlag,
                };
                dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WinTrustData>());
                Marshal.StructureToPtr(data, dataPointer, false);

                var action = NativeMethods.WintrustActionGenericVerifyV2;
                var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, dataPointer);

                // WinVerifyTrust holds state until it is asked to close it.
                var closing = Marshal.PtrToStructure<NativeMethods.WinTrustData>(dataPointer);
                closing.StateAction = NativeMethods.WtdStateActionClose;
                Marshal.StructureToPtr(closing, dataPointer, false);
                NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, dataPointer);

                return result switch
                {
                    TrustEOk => "valid",
                    TrustENosignature => "unsigned",
                    TrustEExplicitDistrust => "untrusted",
                    TrustESubjectNotTrusted => "untrusted",
                    CertEUntrustedroot => "untrusted",
                    CertEChaining => "untrusted",
                    CertEExpired => "expired",
                    CertERevoked => "revoked",
                    _ => "unknown",
                };
            }
            finally
            {
                if (dataPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataPointer);
                }

                if (fileInfoPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(fileInfoPointer);
                }

                Marshal.FreeHGlobal(pathPointer);
            }
        }
    }
}
