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
        public const string CurrentVersion = "0.7.3";
        public const double CurrentVersionNumber = 0.73;

        public static readonly int WinVer = Int32.Parse(Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("CurrentBuildNumber").ToString());

        private static int _winUpdateVer = -1;
        public static int WinUpdateVer
        {
            get
            {
                if (_winUpdateVer != -1)
                    return _winUpdateVer;

                try
                {
                    _winUpdateVer = (int)Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("UBR");
                }
                catch { _winUpdateVer = 0; }

                return _winUpdateVer;
            }
        } 
    }
}
