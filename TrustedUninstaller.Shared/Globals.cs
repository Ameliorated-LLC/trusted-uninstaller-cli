using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Core;
using Microsoft.Win32;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared
{
    public class Globals
    {
        public const string CurrentVersion = "0.8.2";
        public static readonly VersionNumber CurrentVersionNumber = VersionNumber.GetVersionNumber(CurrentVersion);
    }
    [Serializable]
    public class WizardMetadata : Log.ILogMetadata
    {
        public DateTime CreationTime { get; set; }
        public string ClientVersion { get; set; }
        public string WindowsVersion { get; set; }
        public string SystemLanguage { get; set; }
        public string UserLanguage { get; set; }
        public Architecture Architecture { get; set; }
        public string SystemMemory { get; set; }
        public int SystemThreads { get; set; }

        public virtual void Construct()
        {
            ClientVersion = Globals.CurrentVersion;
            WindowsVersion = $"Windows {Win32.SystemInfoEx.WindowsVersion.MajorVersion} {Win32.SystemInfoEx.WindowsVersion.Edition} {Win32.SystemInfoEx.WindowsVersion.BuildNumber}.{Win32.SystemInfoEx.WindowsVersion.UpdateNumber}";
            SystemLanguage = Win32.SystemInfoEx.GetSystemLanguage();
            UserLanguage = Win32.SystemInfoEx.GetUserLanguage();
            SystemMemory = StringUtils.HumanReadableBytes(Win32.SystemInfoEx.GetSystemMemoryInBytes());
            SystemThreads = Environment.ProcessorCount;
            Architecture = Win32.SystemInfoEx.SystemArchitecture;
            CreationTime = DateTime.UtcNow;
        }

        public string Serialize(ISerializer serializer) => serializer.Serialize(this);
    }
}
