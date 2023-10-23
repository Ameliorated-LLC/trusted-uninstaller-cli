using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.Shared
{
    using SLID = Guid; //SLID id declared as typedef GUID SLID; in slpublic.h 

    public static class WinUtil
    {
        public enum SHSTOCKICONID : uint
        {
            SIID_DOCNOASSOC = 0,
            SIID_DOCASSOC = 1,
            SIID_APPLICATION = 2,
            SIID_FOLDER = 3,
            SIID_FOLDEROPEN = 4,
            SIID_DRIVE525 = 5,
            SIID_DRIVE35 = 6,
            SIID_DRIVEREMOVE = 7,
            SIID_DRIVEFIXED = 8,
            SIID_DRIVENET = 9,
            SIID_DRIVENETDISABLED = 10,
            SIID_DRIVECD = 11,
            SIID_DRIVERAM = 12,
            SIID_WORLD = 13,
            SIID_SERVER = 15,
            SIID_PRINTER = 16,
            SIID_MYNETWORK = 17,
            SIID_FIND = 22,
            SIID_HELP = 23,
            SIID_SHARE = 28,
            SIID_LINK = 29,
            SIID_SLOWFILE = 30,
            SIID_RECYCLER = 31,
            SIID_RECYCLERFULL = 32,
            SIID_MEDIACDAUDIO = 40,
            SIID_LOCK = 47,
            SIID_AUTOLIST = 49,
            SIID_PRINTERNET = 50,
            SIID_SERVERSHARE = 51,
            SIID_PRINTERFAX = 52,
            SIID_PRINTERFAXNET = 53,
            SIID_PRINTERFILE = 54,
            SIID_STACK = 55,
            SIID_MEDIASVCD = 56,
            SIID_STUFFEDFOLDER = 57,
            SIID_DRIVEUNKNOWN = 58,
            SIID_DRIVEDVD = 59,
            SIID_MEDIADVD = 60,
            SIID_MEDIADVDRAM = 61,
            SIID_MEDIADVDRW = 62,
            SIID_MEDIADVDR = 63,
            SIID_MEDIADVDROM = 64,
            SIID_MEDIACDAUDIOPLUS = 65,
            SIID_MEDIACDRW = 66,
            SIID_MEDIACDR = 67,
            SIID_MEDIACDBURN = 68,
            SIID_MEDIABLANKCD = 69,
            SIID_MEDIACDROM = 70,
            SIID_AUDIOFILES = 71,
            SIID_IMAGEFILES = 72,
            SIID_VIDEOFILES = 73,
            SIID_MIXEDFILES = 74,
            SIID_FOLDERBACK = 75,
            SIID_FOLDERFRONT = 76,
            SIID_SHIELD = 77,
            SIID_WARNING = 78,
            SIID_INFO = 79,
            SIID_ERROR = 80,
            SIID_KEY = 81,
            SIID_SOFTWARE = 82,
            SIID_RENAME = 83,
            SIID_DELETE = 84,
            SIID_MEDIAAUDIODVD = 85,
            SIID_MEDIAMOVIEDVD = 86,
            SIID_MEDIAENHANCEDCD = 87,
            SIID_MEDIAENHANCEDDVD = 88,
            SIID_MEDIAHDDVD = 89,
            SIID_MEDIABLURAY = 90,
            SIID_MEDIAVCD = 91,
            SIID_MEDIADVDPLUSR = 92,
            SIID_MEDIADVDPLUSRW = 93,
            SIID_DESKTOPPC = 94,
            SIID_MOBILEPC = 95,
            SIID_USERS = 96,
            SIID_MEDIASMARTMEDIA = 97,
            SIID_MEDIACOMPACTFLASH = 98,
            SIID_DEVICECELLPHONE = 99,
            SIID_DEVICECAMERA = 100,
            SIID_DEVICEVIDEOCAMERA = 101,
            SIID_DEVICEAUDIOPLAYER = 102,
            SIID_NETWORKCONNECT = 103,
            SIID_INTERNET = 104,
            SIID_ZIPFILE = 105,
            SIID_SETTINGS = 106,
            SIID_DRIVEHDDVD = 132,
            SIID_DRIVEBD = 133,
            SIID_MEDIAHDDVDROM = 134,
            SIID_MEDIAHDDVDR = 135,
            SIID_MEDIAHDDVDRAM = 136,
            SIID_MEDIABDROM = 137,
            SIID_MEDIABDR = 138,
            SIID_MEDIABDRE = 139,
            SIID_CLUSTEREDDRIVE = 140,
            SIID_MAX_ICONS = 175
        }

        [Flags]
        public enum SHGSI : uint
        {
            SHGSI_ICONLOCATION = 0,
            SHGSI_ICON = 0x000000100,
            SHGSI_SYSICONINDEX = 0x000004000,
            SHGSI_LINKOVERLAY = 0x000008000,
            SHGSI_SELECTED = 0x000010000,
            SHGSI_LARGEICON = 0x000000000,
            SHGSI_SMALLICON = 0x000000001,
            SHGSI_SHELLICONSIZE = 0x000000004
        }

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHSTOCKICONINFO
        {
            public UInt32 cbSize;
            public IntPtr hIcon;
            public Int32 iSysIconIndex;
            public Int32 iIcon;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260 /*MAX_PATH*/)]
            public string szPath;
        }

        [DllImport("Shell32.dll", SetLastError = false)]
        public static extern Int32 SHGetStockIconInfo(SHSTOCKICONID siid, SHGSI uFlags, ref SHSTOCKICONINFO psii);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool DestroyIcon(IntPtr hIcon);


        public static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static string GetUserName()
        {
            var wi = WindowsIdentity.GetCurrent();
            var groups = from g in wi.Groups
                select new SecurityIdentifier(g.Value)
                    .Translate(typeof(NTAccount)).Value;
            var msAccount = (from g in groups
                where g.StartsWith(@"MicrosoftAccount\")
                select g).FirstOrDefault();
            return msAccount == null ? Environment.UserName : msAccount.Substring(@"MicrosoftAccount\".Length);
        }
        
        public static bool IsLocalAccount()
        {
            var wi = WindowsIdentity.GetCurrent();
            var groups = from g in wi.Groups
                select new SecurityIdentifier(g.Value)
                    .Translate(typeof(NTAccount)).Value;
            var msAccount = (from g in groups
                where g.StartsWith(@"MicrosoftAccount\")
                select g).FirstOrDefault();
            return msAccount == null;
        }


        public enum SL_GENUINE_STATE
        {
            SL_GEN_STATE_IS_GENUINE = 0,
            // SL_GEN_STATE_INVALID_LICENSE = 1,
            // SL_GEN_STATE_TAMPERED = 2,
            SL_GEN_STATE_LAST = 3
        }
        
        [DllImport("Slwga.dll", EntryPoint = "SLIsGenuineLocal", CharSet = CharSet.None, ExactSpelling =
 false, SetLastError = false, PreserveSig = true, CallingConvention = CallingConvention.Winapi, BestFitMapping =
 false, ThrowOnUnmappableChar = false)]
        [PreserveSigAttribute()]
        internal static extern uint SLIsGenuineLocal(ref SLID slid, [In, Out] ref SL_GENUINE_STATE genuineState, IntPtr val3);

        public static bool IsGenuineWindows()
        {
            // Microsoft-Windows-Security-SPP GUID
            // http://technet.microsoft.com/en-us/library/dd772270.aspx
            var windowsSlid = new SLID("55c92734-d682-4d71-983e-d6ec3f16059f"); 
            var genuineState = SL_GENUINE_STATE.SL_GEN_STATE_LAST;
            var resultInt = SLIsGenuineLocal(ref windowsSlid, ref genuineState, IntPtr.Zero);
#if DEBUG
            return true;
#else
            return resultInt == 0 && genuineState == SL_GENUINE_STATE.SL_GEN_STATE_IS_GENUINE;
#endif
            
        }

        private static IEnumerable<string> GetWindowsGroups(WindowsIdentity id)
        {
            var irc = id.Groups ?? new IdentityReferenceCollection();
            return irc.Select(ir => (NTAccount) ir.Translate(typeof(NTAccount))).Select(acc => acc.Value).ToList();
        }

        public static bool HasWindowsGroup(string groupName)
        {
            var appDomain = Thread.GetDomain();
            appDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            var currentPrincipal = (WindowsPrincipal) Thread.CurrentPrincipal;
            var groups = GetWindowsGroups((WindowsIdentity) currentPrincipal.Identity);
            return groups.Any(group => group == groupName);
        }

        public static bool IsTrustedInstaller()
        {
            return HasWindowsGroup(@"NT SERVICE\TrustedInstaller");
        }

        public static bool RelaunchAsTrustedInstaller()
        {
            var controller = new ServiceController("TrustedInstaller");
            if (controller.Status != ServiceControllerStatus.Running)
            {
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running);
            }

            var targetProcess = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();

            if (targetProcess == null)
            {
                return false;
            }

            var currentProcess = Process.GetCurrentProcess();
            var currentModule = currentProcess.MainModule;

            if (currentModule == null)
            {
                return false;
            }

            var currentExecutable = currentModule.FileName;
            return NativeProcess.StartProcess(currentExecutable, targetProcess.Id, AmeliorationUtil.Playbook.Path);
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(
            IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode,
            SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        public static extern int CloseServiceHandle(IntPtr hSCObject);

        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        private const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;


        public static void ChangeStartMode(ServiceController svc, ServiceStartMode mode)
        {
            var scManagerHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (scManagerHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Manager Error");
            }

            var serviceHandle = OpenService(
                scManagerHandle,
                svc.ServiceName,
                SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new ExternalException("Open Service Error");
            }

            var result = ChangeServiceConfig(
                serviceHandle,
                SERVICE_NO_CHANGE,
                (uint)mode,
                SERVICE_NO_CHANGE,
                null,
                null,
                IntPtr.Zero,
                null,
                null,
                null,
                null);

            if (result == false)
            {
                var nError = Marshal.GetLastWin32Error();
                var win32Exception = new Win32Exception(nError);
                throw new ExternalException("Could not change service start type: "
                    + win32Exception.Message);
            }

            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scManagerHandle);
        }

        [StructLayout(LayoutKind.Sequential)]
        struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        const int RmRebootReasonNone = 0;
        const int CCH_RM_MAX_APP_NAME = 255;
        const int CCH_RM_MAX_SVC_NAME = 63;

        enum RM_APP_TYPE
        {
            RmUnknownApp = 0,
            RmMainWindow = 1,
            RmOtherWindow = 2,
            RmService = 3,
            RmExplorer = 4,
            RmConsole = 5,
            RmCritical = 1000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
            public string strAppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
            public string strServiceShortName;

            public RM_APP_TYPE ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        static extern int RmRegisterResources(uint pSessionHandle,
            UInt32 nFiles,
            string[] rgsFilenames,
            UInt32 nApplications,
            [In] RM_UNIQUE_PROCESS[] rgApplications,
            UInt32 nServices,
            string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
        static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll")]
        static extern int RmGetList(uint dwSessionHandle,
            out uint pnProcInfoNeeded,
            ref uint pnProcInfo,
            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
            ref uint lpdwRebootReasons);

        /// <summary>
        /// Find out what process(es) have a lock on the specified file.
        /// </summary>
        /// <param name="path">Path of the file.</param>
        /// <returns>Processes locking the file</returns>
        /// <remarks>See also:
        /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
        /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
        /// 
        /// </remarks>
        public static List<Process> WhoIsLocking(string path)
        {
            string key = Guid.NewGuid().ToString();
            List<Process> processes = new List<Process>();

            int res = RmStartSession(out uint handle, 0, key);
            if (res != 0)
            {
                ErrorLogger.WriteToErrorLog("Could not begin restart session. Unable to determine file locker.",
                    Environment.StackTrace, $"Error while attempting to get locking processes of file {path}");
                throw new Exception("Could not begin restart session.  Unable to determine file locker.");
            }

            try
            {
                const int ERROR_MORE_DATA = 234;
                uint pnProcInfoNeeded = 0,
                    pnProcInfo = 0,
                    lpdwRebootReasons = RmRebootReasonNone;

                string[] resources = new string[] { path }; // Just checking on one resource.

                res = RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);

                if (res != 0) throw new Exception("Could not register resource.");

                //Note: there's a race condition here -- the first call to RmGetList() returns
                //      the total number of process. However, when we call RmGetList() again to get
                //      the actual processes this number may have increased.
                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                if (res == ERROR_MORE_DATA)
                {
                    // Create an array to store the process results
                    RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded + 3];
                    pnProcInfo = pnProcInfoNeeded;

                    // Get the list
                    res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                    if (res == 0)
                    {
                        processes = new List<Process>((int)pnProcInfo);

                        // Enumerate all of the results and add them to the 
                        // list to be returned
                        for (int i = 0; i < pnProcInfo; i++)
                        {
                            try
                            {
                                processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                            }
                            // catch the error -- in case the process is no longer running
                            catch (ArgumentException) { }
                        }
                    }
                    else throw new Exception("Could not list processes locking resource: " + res);
                }
                else if (res != 0)
                    throw new Exception("Could not list processes locking resource. Could not get size of result." + $" Result value: {res}");
            }
            finally
            {
                RmEndSession(handle);
            }

            return processes;
        }

        /// <summary>
        /// Finds active anti-viruses in the system.
        /// </summary>
        /// <returns>a list of ProviderStatus.</returns>
        /// <remarks>See also:
        /// https://jdhitsolutions.com/blog/powershell/5187/get-antivirus-product-status-with-powershell/
        /// https://docs.microsoft.com/en-us/windows/win32/api/iwscapi/ne-iwscapi-wsc_security_product_state?redirectedfrom=MSDN
        /// https://mspscripts.com/get-installed-antivirus-information-2/
        /// https://social.msdn.microsoft.com/Forums/pt-BR/6501b87e-dda4-4838-93c3-244daa355d7c/wmisecuritycenter2-productstate?forum=vblanguage
        /// https://stackoverflow.com/questions/4700897/wmi-security-center-productstate-clarification/4711211
        /// https://blogs.msdn.microsoft.com/alejacma/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript/#comment-442
        /// https://www.magnumdb.com/search?q=parent:WSC_SECURITY_PRODUCT_STATE
        /// https://web.archive.org/web/20190121133247/http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
        /// </remarks>
        public static List<ProviderStatus> GetEnabledAvList(bool ensureWMI = true)
        {
            if (ensureWMI)
            {
                var svc = new ServiceController("Winmgmt");
                ChangeStartMode(svc, ServiceStartMode.Automatic);
            }
            
            List<ProviderStatus> avList = new List<ProviderStatus>();
            string computer = Environment.MachineName;
            string wmipath = @"\\" + computer + @"\root\SecurityCenter2";
            string query = @"SELECT * FROM AntivirusProduct WHERE displayName != ""Windows Defender""";

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(wmipath, query))
                {
                    ManagementObjectCollection results = searcher.Get();
                    foreach (var o in results)
                    {
                        // You can find if an AV is active or not by accessing the hex code of the productState
                        // (from the right) 19th bit == Anti Virus is on
                        // (from the right) 13th bit == On Access Scanning
                        // 00000000 00000[1]10 000[1]0000 000[0]0000
                        // 19th bit (yes) = Av on
                        // 13th bit (yes) = On Access Scanning
                        // The third byte defines if the .dat file is up-to-date
                        var result = (ManagementObject)o;
                        var productState = result["productState"];
                        string hex = Hex(Convert.ToInt32(productState));
                        string bin = Binary(Convert.ToInt32(productState));
                        string reversed = Reverse(bin);
                        var enabled = GetBit(reversed, 18);
                        var scanning = GetBit(reversed, 12);
                        var outdated = GetBit(reversed, 4);

                        static string Binary(int value)
                        {
                            return Convert.ToString(value, 2).PadLeft(24, '0');
                        }

                        static string Hex(int value)
                        {
                            return Convert.ToString(value, 16).PadLeft(6, '0');
                        }

                        static bool GetBit(string value, int index)
                        {
                            return value.Substring(index, 1).Equals("1");
                        }

                        static string Reverse(string value)
                        {
                            return new string(value.Reverse().ToArray());
                        }

                        if (!enabled) continue;
                        var av = new ProviderStatus()
                        {
                            DisplayName = result["displayName"].ToString(),
                            AVStatus = enabled ? AVStatusFlags.Enabled : AVStatusFlags.Unknown,
                            SecurityProvider = ProviderFlags.ANTIVIRUS,
                            SignatureStatus = outdated ? SignatureStatusFlags.OutOfDate : SignatureStatusFlags.UpToDate,
                            FileExists = File.Exists(result["pathToSignedProductExe"].ToString())
                        };
                        avList.Add(av);
                    }
                }
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "Error while retrieving the AV list.");
            }

            return avList;
        }

        //Checks if Visual C++ redistributable is installed. 
        public static bool IsVCInstalled()
        {
            string dependenciesPath = @"SOFTWARE\Classes\Installer\Dependencies";

            using (RegistryKey dependencies = Registry.LocalMachine.OpenSubKey(dependenciesPath))
            {
                if (dependencies == null) return false;

                foreach (string subKeyName in dependencies.GetSubKeyNames().Where(n => !n.ToLower().Contains("dotnet") && !n.ToLower().Contains("microsoft")))
                {
                    using (RegistryKey subDir = Registry.LocalMachine.OpenSubKey(dependenciesPath + "\\" + subKeyName))
                    {
                        var value = subDir.GetValue("DisplayName")?.ToString() ?? null;
                        if (string.IsNullOrEmpty(value))
                        {
                            continue;
                        }
                        if (Environment.Is64BitOperatingSystem)
                        {
                            if (Regex.IsMatch(value, @"C\+\+ 2015.*\((x64|x86)\)"))
                            {
                                return true;
                            }
                        }
                        else
                        {
                            if (Regex.IsMatch(value, @"C\+\+ 2015.*\(x86\)"))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }
        public static async Task RemoveProtectionAsync()
        {
            var cmdAction = new CmdAction();

            if (AmeliorationUtil.UseKernelDriver)
            {
                /*
                if (!IsVCInstalled())
                {
                    Console.WriteLine(Environment.NewLine + "Installing VC 15...");
                    try
                    {
                        //Install Visual C++ 2015 redistributable package silently
                        cmdAction.Command = "vc_redist.x64.exe /q /norestart";
                        cmdAction.RunTaskOnMainThread();
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "Error while installing VC 15.");
                        throw;
                    }
                }
                */

                try
                {
                    Console.WriteLine(Environment.NewLine + "Installing driver...");
                    cmdAction.Command = Environment.Is64BitOperatingSystem
                        ? $"ProcessHacker\\x64\\ProcessHacker.exe -s -installkph"
                        : $"ProcessHacker\\x86\\ProcessHacker.exe -s -installkph";
                    cmdAction.RunTaskOnMainThread();

                    await AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                        { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\KProcessHacker2", Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 });
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "ProcessHacker ran into an error while installing its driver.");
                    throw;
                }
            }
        }

        public static async void CheckKph()
        {
            if (!AmeliorationUtil.UseKernelDriver || new RegistryKeyAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\KProcessHacker2", Operation = RegistryKeyOperation.Add }.GetStatus() == UninstallTaskStatus.Completed)
                return;
            
            Console.WriteLine(Environment.NewLine + "Installing driver...");
            var cmdAction = new CmdAction();
            cmdAction.Command = Environment.Is64BitOperatingSystem
                ? $"ProcessHacker\\x64\\ProcessHacker.exe -s -installkph"
                : $"ProcessHacker\\x86\\ProcessHacker.exe -s -installkph";
            cmdAction.RunTaskOnMainThread();
            
            await AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\KProcessHacker2", Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 });
        }

        private const int GWL_STYLE = -16;
        private const int WS_SYSMENU = 0x80000;
        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")]
        private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        //public static void RemoveCloseButton(Window window)
        //{
            //var hwnd = new WindowInteropHelper(window).Handle;
            //SetWindowLong(hwnd, GWL_STYLE, GetWindowLong(hwnd, GWL_STYLE) & ~WS_SYSMENU);
        //}

        public static bool IsVM()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
                {
                    using (var items = searcher.Get())
                    {
                        foreach (var item in items)
                        {
                            string manufacturer = item["Manufacturer"].ToString().ToLower();
                            if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                                || manufacturer.Contains("vmware")
                                || item["Model"].ToString() == "VirtualBox")
                            {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "Error while checking if running system is a VM.");
                return false;
            }
        }

        public static async Task UninstallDriver()
        {
            if (AmeliorationUtil.UseKernelDriver == false)
                return;
            AmeliorationUtil.UseKernelDriver = false;
            
            CmdAction cmdAction = new CmdAction();
            try
            {
                Console.WriteLine("Removing driver...");
                cmdAction.Command = Environment.Is64BitOperatingSystem
                    ? $"ProcessHacker\\x64\\ProcessHacker.exe -s -uninstallkph"
                    : $"ProcessHacker\\x86\\ProcessHacker.exe -s -uninstallkph";
                cmdAction.RunTaskOnMainThread();
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "ProcessHacker ran into an Error while uninstalling the driver.");
                throw;
            }
        }
        
        public class RegistryManager
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

            [DllImport("advapi32.dll", SetLastError = true)]
            static extern int RegSaveKey(IntPtr hKey, string lpFile, uint securityAttrPtr = 0);

            [DllImport("advapi32.dll", SetLastError = true)]
            static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

            [DllImport("ntdll.dll", SetLastError = true)]
            static extern IntPtr RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

            [DllImport("advapi32.dll")]
            static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref UInt64 lpLuid);

            [DllImport("advapi32.dll")]
            static extern bool LookupPrivilegeValue(IntPtr lpSystemName, string lpName, ref UInt64 lpLuid);

            public static void LoadFromFile(string path, bool classHive = false)
            {
                var parentKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                string name;

                if (path.Contains("Users\\Default\\")) name = classHive ? "AME_UserHive_Default_Classes" : "AME_UserHive_Default";
                else name = classHive ? "AME_UserHive_" + (HivesLoaded + 1) + "_Classes" : "AME_UserHive_" + (HivesLoaded + 1);

                IntPtr parentHandle = parentKey.Handle.DangerousGetHandle();
                RegLoadKey(parentHandle, name, path);
                HivesLoaded++;
            }
            private static void AcquirePrivileges()
            {
                ulong luid = 0;
                bool throwaway;
                LookupPrivilegeValue(IntPtr.Zero, "SeRestorePrivilege", ref luid);
                RtlAdjustPrivilege((int)luid, true, false, out throwaway);
                LookupPrivilegeValue(IntPtr.Zero, "SeBackupPrivilege", ref luid);
                RtlAdjustPrivilege((int)luid, true, false, out throwaway);
            }
            private static void ReturnPrivileges()
            {
                ulong luid = 0;
                bool throwaway;
                LookupPrivilegeValue(IntPtr.Zero, "SeRestorePrivilege", ref luid);
                RtlAdjustPrivilege((int)luid, false, false, out throwaway);
                LookupPrivilegeValue(IntPtr.Zero, "SeBackupPrivilege", ref luid);
                RtlAdjustPrivilege((int)luid, false, false, out throwaway);
            }

            private static bool HivesHooked;
            private static int HivesLoaded;
            public static async void HookUserHives()
            {
                try
                {
                    if (HivesHooked || WinUtil.IsTrustedInstaller() || RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default).GetSubKeyNames().Any(x => x.StartsWith("AME_UserHive_"))) return;
                    HivesHooked = true;

                    var usersDir = Environment.GetEnvironmentVariable("SYSTEMDRIVE") + "\\Users";

                    var ignoreList = new List<string>() { "Default User", "Public", "All Users" };
                    var userDirs = Directory.GetDirectories(usersDir).Where(x => !ignoreList.Contains(x.Split('\\').Last())).ToList();

                    var userKeys = Registry.Users.GetSubKeyNames().Where(x => x.StartsWith("S-"));

                    foreach (var userKey in userKeys)
                    {

                        try
                        {
                            var userEnv = Registry.Users.OpenSubKey(userKey).OpenSubKey("Volatile Environment");
                            userDirs.Remove((string)userEnv.GetValue("USERPROFILE"));
                        }
                        catch (Exception) { }
                    }
                    
                    if (userDirs.Any()) AcquirePrivileges();
                    foreach (var userDir in userDirs)
                    {
                        if (!File.Exists($"{userDir}\\NTUSER.DAT"))
                        {
                            ErrorLogger.WriteToErrorLog($"NTUSER.DAT file not found in user folder '{userDir}'.",
                                Environment.StackTrace, $"Error attempting to load user registry hive.");
                            continue;
                        }
                        LoadFromFile($"{userDir}\\NTUSER.DAT");

                        if (userDir.EndsWith("\\Default"))
                        {
                            try
                            {
                                if (!Directory.Exists($@"{userDir}\AppData\Local\Microsoft\Windows")) Directory.CreateDirectory($@"{userDir}\AppData\Local\Microsoft\Windows");
                                var fs = File.Create($@"{userDir}\AppData\Local\Microsoft\Windows" + @"\UsrClass.dat");
                            
                                var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("TrustedUninstaller.Shared.Properties.UsrClass.dat");
                                resource.CopyTo(fs);
                            
                                fs.Close();
                            }
                            catch (Exception e)
                            {
                                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                                    $"Failed to create default user class hive.", userDir);
                            }
                        }
                    
                        if (!File.Exists($@"{userDir}\AppData\Local\Microsoft\Windows\UsrClass.dat"))
                        {
                            ErrorLogger.WriteToErrorLog($@"UsrClass.dat file not found in user appdata folder '{userDir}\AppData\Local\Microsoft\Windows'.",
                                Environment.StackTrace, $"Error attempting to load user classes registry hive.");
                            continue;
                        }
                        LoadFromFile($@"{userDir}\AppData\Local\Microsoft\Windows\UsrClass.dat", true);
                    }
                    if (userDirs.Any()) ReturnPrivileges();
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                        $"Critical error while attempting to mount user hives.");
                    Console.WriteLine(":AME-ERROR: Failure while mounting user registry hives.");
                }
            }

            public static async void UnhookUserHives()
            {
                try
                {
                    var usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                    var userHives = usersKey.GetSubKeyNames().Where(x => x.StartsWith("AME_UserHive_")).ToList();

                    if (userHives.Any()) AcquirePrivileges();
                    foreach (var userHive in userHives)
                    {
                        RegUnLoadKey(usersKey.Handle.DangerousGetHandle(), userHive);
                    }
                    if (userHives.Any()) ReturnPrivileges();
                
                    usersKey.Close();
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                        $"Critical error while attempting to unmount user hives.");
                    Console.WriteLine(":AME-ERROR: Failure while unmounting user registry hives.");
                }
            }
        }
        
        
    public class HttpProgressClient : IDisposable
    {
        private string _downloadUrl;
        private string _destinationFilePath;

        public HttpClient Client;

        public delegate void ProgressChangedHandler(long? totalFileSize, long totalBytesDownloaded, double? progressPercentage);

        public event ProgressChangedHandler ProgressChanged;

        public HttpProgressClient()
        {
            Client = new HttpClient { Timeout = TimeSpan.FromDays(1) };
        }

        public async Task StartDownload(string downloadUrl, string destinationFilePath, long? size = null)
        {
            _downloadUrl = downloadUrl;
            _destinationFilePath = destinationFilePath;
            
            using (var response = await Client.GetAsync(_downloadUrl, HttpCompletionOption.ResponseHeadersRead))
                await DownloadFileFromHttpResponseMessage(response, size);
        }

        public Task<HttpResponseMessage> GetAsync(string link)
        {
            return Client.GetAsync(link);
        }
        
        private async Task DownloadFileFromHttpResponseMessage(HttpResponseMessage response, long? size)
        {
            response.EnsureSuccessStatusCode();
            
            if (!size.HasValue)
                size = response.Content.Headers.ContentLength;

            using (var contentStream = await response.Content.ReadAsStreamAsync())
                await ProcessContentStream(size, contentStream);
        }

        private async Task ProcessContentStream(long? totalDownloadSize, Stream contentStream)
        {
            var totalBytesRead = 0L;
            var readCount = 0L;
            var buffer = new byte[8192];
            var isMoreToRead = true;

            using (var fileStream = new FileStream(_destinationFilePath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true))
            {
                do
                {
                    var bytesRead = await contentStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                    {
                        isMoreToRead = false;
                        TriggerProgressChanged(totalDownloadSize, totalBytesRead);
                        continue;
                    }
                    
                    await fileStream.WriteAsync(buffer, 0, bytesRead);

                    totalBytesRead += bytesRead;
                    readCount += 1;
                    
                    if (readCount % 50 == 0)
                        TriggerProgressChanged(totalDownloadSize, totalBytesRead);
                }
                while (isMoreToRead);
            }
        }

        private void TriggerProgressChanged(long? totalDownloadSize, long totalBytesRead)
        {
            if (ProgressChanged == null)
                return;

            double? progressPercentage = null;
            if (totalDownloadSize.HasValue)
            {
                progressPercentage = Math.Round((double)totalBytesRead / totalDownloadSize.Value * 100, 2);
            }
                

            ProgressChanged(totalDownloadSize, totalBytesRead, progressPercentage);
        }

        public void Dispose()
        {
            Client?.Dispose();
        }
    }
    }
}
