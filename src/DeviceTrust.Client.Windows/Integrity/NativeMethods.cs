using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DeviceTrust.Client.Windows.Integrity
{
    /// <summary>The Win32 entry points the Windows probes need.</summary>
    [SupportedOSPlatform("windows")]
    internal static class NativeMethods
    {
        internal const uint WtdUiNone = 2;
        internal const uint WtdRevokeNone = 0;
        internal const uint WtdChoiceFile = 1;
        internal const uint WtdStateActionVerify = 1;
        internal const uint WtdStateActionClose = 2;
        internal const uint WtdSaferFlag = 0x100;

        internal static readonly Guid WintrustActionGenericVerifyV2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CheckRemoteDebuggerPresent(IntPtr processHandle, ref bool debuggerPresent);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        internal static extern int WinVerifyTrust(IntPtr window, [In] ref Guid action, [In] IntPtr data);

        [StructLayout(LayoutKind.Sequential)]
        internal struct WinTrustFileInfo
        {
            internal uint StructSize;
            internal IntPtr FilePath;
            internal IntPtr FileHandle;
            internal IntPtr KnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WinTrustData
        {
            internal uint StructSize;
            internal IntPtr PolicyCallbackData;
            internal IntPtr SipClientData;
            internal uint UiChoice;
            internal uint RevocationChecks;
            internal uint UnionChoice;
            internal IntPtr FileInfoPtr;
            internal uint StateAction;
            internal IntPtr StateData;
            internal IntPtr UrlReference;
            internal uint ProviderFlags;
            internal uint UiContext;
            internal IntPtr SignatureSettings;
        }
    }
}
