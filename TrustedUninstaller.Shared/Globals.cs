using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TrustedUninstaller.Shared
{
    public class Globals
    {
        public const string CurrentVersion = "0.7.2";
        public const double CurrentVersionNumber = 0.72;
#if DEBUG
        public static readonly int WinVer = 19045;
#else
        public static readonly int WinVer = Int32.Parse(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("CurrentBuildNumber").ToString());
#endif        
    }
}
