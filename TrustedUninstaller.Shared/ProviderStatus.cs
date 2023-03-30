using System;
using System.Runtime.InteropServices;

namespace TrustedUninstaller.Shared
{
    //Byte 0
    [Flags]
    public enum SignatureStatusFlags : byte
    {
        UpToDate = 0,
        OutOfDate = 16
    }

    // Byte 1
    [Flags]
    public enum AVStatusFlags : byte
    {
        Unknown = 1,
        Enabled = 16
    }

    // Byte 2
    [Flags]
    public enum ProviderFlags : byte
    {
        FIREWALL = 1,
        AUTOUPDATE_SETTINGS = 2,
        ANTIVIRUS = 4,
        ANTISPYWARE = 8,
        INTERNET_SETTINGS = 16,
        USER_ACCOUNT_CONTROL = 32,
        SERVICE = 64,
        NONE = 0,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProviderStatus
    {
        public SignatureStatusFlags SignatureStatus;
        public AVStatusFlags AVStatus;
        public ProviderFlags SecurityProvider;
        public string DisplayName;
    }
}
