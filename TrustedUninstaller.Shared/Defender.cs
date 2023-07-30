using System.IO;
using System.Windows;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace TrustedUninstaller.Shared
{
    public static class Defender
    {
        private static KeyValuePair<string, ProcessType>[] DefenderItems =
        {
            new KeyValuePair<string, ProcessType>("CompatTelRunner", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("DWWIN", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("DeviceCensus", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("GameBarPresenceWriter", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("SecurityHealthHost", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("SecurityHealthService", ProcessType.Exe), // SecurityHealthService
            new KeyValuePair<string, ProcessType>("SecurityHealthSystray", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("smartscreen", ProcessType.Exe),
            //new KeyValuePair<string, ProcessType>("MpCmdRun", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("NisSrv", ProcessType.Exe),
            new KeyValuePair<string, ProcessType>("wscsvc", ProcessType.Service), // Windows Security Center
            new KeyValuePair<string, ProcessType>("WinDefend", ProcessType.Service), // Microsoft Defender Antivirus Service
            new KeyValuePair<string, ProcessType>("Sense", ProcessType.Service), // Windows Defender Advanced Threat Protection Service
            new KeyValuePair<string, ProcessType>("WdNisSvc", ProcessType.Service), // Microsoft Defender Antivirus Network Inspection Service
            new KeyValuePair<string, ProcessType>("WdNisDrv", ProcessType.Device), // Microsoft Defender Antivirus Network Inspection Driver
            //new KeyValuePair<string, ProcessType>("WdFilter", ProcessType.Device), // Windows Defender Disk inspection Minifilter,
        };
        
        //[DllImport("Unlocker.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        //private static extern bool EzUnlockFileW(string path);

        private static readonly string[] defenderDirs =
        {
            Environment.ExpandEnvironmentVariables(@"%ProgramData%\Microsoft\Windows Defender"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Windows Defender"),
            Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Windows Defender Advanced Threat Protection")
        };

        private static void RenameAllChildFiles(string dir, bool reset)
        {
            foreach (var subDir in Directory.GetDirectories(dir))
            {
                try
                {
                    RenameAllChildFiles(subDir, reset);
                }
                catch (Exception e)
                {
                }
            }

            foreach (var file in Directory.GetFiles(dir, reset ? "*.oldx" : "*", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.Move(file, reset ? file.Substring(0, file.Length - 4) : file + ".oldx");
                }
                catch (Exception e)
                {
                }
            }
        }
        public static void Cripple()
        {
            foreach (var defenderDir in defenderDirs)
            {
                try
                {
                    RenameAllChildFiles(defenderDir, false);
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog("Error renaming files: " + e.GetType() + " " + e.Message, null, "Defender cripple warning", defenderDir);
                }
            }
        }


        public static void DeCripple()
        {
            foreach (var defenderDir in defenderDirs)
            {
                try
                {
                    RenameAllChildFiles(defenderDir, true);
                }
                catch (Exception e)
                {
                }
            }
        }
        
        public static bool Disable()
        {
            bool restartRequired = true;

            foreach (var service in DefenderItems.Where(x => x.Value == ProcessType.Service || x.Value == ProcessType.Device).Select(x => x.Key))
            {
                AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                    { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + service, Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD, Operation = RegistryValueOperation.Set }).Wait();
            }
            
            AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }).Wait();
            AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                { KeyName = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", Value = "EnableSmartScreen", Data = 0, Type = RegistryValueType.REG_DWORD }).Wait();

            try
            {
                new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "ProductAppDataPath", Operation = RegistryValueOperation.Delete }.RunTask().Wait();
                new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "InstallLocation", Operation = RegistryValueOperation.Delete }.RunTask().Wait();
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("Error removing Defender install values: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait cmd /c \"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\" /v \"ProductAppDataPath\" /f &" +
                        " reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\" /v \"InstallLocation\" /f\"",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "InstallLocation", Operation = RegistryValueOperation.Delete }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Could not remove defender install values.");
            }

            try
            {
                new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("First WinDefend service removal failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /f",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                {
                    ErrorLogger.WriteToErrorLog("WinDefend service removal failed." + e.GetType(), null, "Defender disable warning");

                    try
                    {
                        new RegistryValueAction()
                            { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.RunTask().Wait();

                        if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.GetStatus() !=
                            UninstallTaskStatus.Completed)
                            throw new Exception("Unknown reason");
                    }
                    catch (Exception ex)
                    {
                        ErrorLogger.WriteToErrorLog("First WinDefend disable failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                        new RunAction()
                        {
                            RawPath = Directory.GetCurrentDirectory(),
                            Exe = $"NSudoLC.exe",
                            Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d 4 /f",
                            CreateWindow = false
                        }.RunTask().Wait();

                        if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.GetStatus() !=
                            UninstallTaskStatus.Completed)
                            throw new Exception("Could not disable WinDefend service.");
                    }
                }
            }

            try
            {
                // MpOAV.dll is normally in use by a lot of processes. This prevents that.
                new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("First MpOAV mapping removal failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = @"-U:T -P:E -M:S -Priority:RealTime -ShowWindowMode:Hide -Wait reg delete ""HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32"" /f",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    ErrorLogger.WriteToErrorLog("Could not remove MpOAV mapping.", null, "Defender disable warning");
            }

            try
            {
                // smartscreenps.dll is sometimes in use by a lot of processes. This prevents that.
                new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.RunTask().Wait();

                // This may not be important.
                new RegistryKeyAction() { KeyName = @"HKCR\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.RunTask().Wait();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.AppReputationService" }.RunTask().Wait();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.EventLogger" }.RunTask().Wait();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.UriReputationService" }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("First smartscreenps mapping removal failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait cmd /c \"reg delete \"HKCR\\CLSID\\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\\InprocServer32\" /f &" +
                        "reg delete \"HKCR\\WOW6432Node\\CLSID\\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\\InprocServer32\" /f &" +
                        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Internal.Security.SmartScreen.AppReputationService\" /f &" +
                        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Internal.Security.SmartScreen.EventLogger\" /f &" +
                        "reg delete \"HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\ActivatableClassId\\Windows.Internal.Security.SmartScreen.UriReputationService\" /f\"",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    ErrorLogger.WriteToErrorLog("Could not remove smartscreenps mapping.", null, "Defender disable warning");
            }


            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.RunTask().Wait();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("First memory integrity disable failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"" /v Enabled /d 0 /f",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    ErrorLogger.WriteToErrorLog("Could not disable memory integrity.", null, "Defender disable warning");
            }
            
            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.RunTask().Wait();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("First memory integrity disable failed: " + e.GetType() + " " + e.Message, null, "Defender disable warning");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"" /v Enabled /d 0 /f",
                    CreateWindow = false
                }.RunTask().Wait();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    ErrorLogger.WriteToErrorLog("Could not disable memory integrity.", null, "Defender disable warning");
            }

            AmeliorationUtil.SafeRunAction(new RegistryValueAction()
            {
                KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                Value = "VulnerableDriverBlocklistEnable",
                Data = 0,
            }).Wait();

            return restartRequired;
        }

        public static void GetDefenderPrivileges()
        {
            IntPtr impersonatedTokenHandle = IntPtr.Zero;

            ImpersonateProcessByName("winlogon", ref impersonatedTokenHandle);

            ImpersonateProcessByName("lsass", ref impersonatedTokenHandle);

            impersonatedTokenHandle = CreateWinDefendToken(impersonatedTokenHandle, false);

            PInvoke.ImpersonateLoggedOnUser(impersonatedTokenHandle);
        }
        
        public static IntPtr StartElevatedProcess(string exe, string command)
        {
            IntPtr impersonatedTokenHandle = IntPtr.Zero;

            ImpersonateProcessByName("winlogon", ref impersonatedTokenHandle);

            ImpersonateProcessByName("lsass", ref impersonatedTokenHandle);

            impersonatedTokenHandle = CreateWinDefendToken(impersonatedTokenHandle, true);

            var startupInfo = new PInvoke.STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);
            startupInfo.lpDesktop = "Winsta0\\Default";

            if (!String.IsNullOrEmpty(command))
                command = command.Insert(0, " ");

            if (!PInvoke.CreateProcessWithToken(
                    impersonatedTokenHandle,
                    PInvoke.LogonFlags.WithProfile,
                    null,
                    $@"""{exe}""{command}",
                    0,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref startupInfo,
                    out PInvoke.PROCESS_INFORMATION processInformation))
            {
                throw new Exception(Marshal.GetLastWin32Error().ToString());
            }

            PInvoke.CloseHandle(processInformation.hThread);

            return processInformation.hProcess;
        }

        public static uint WaitForProcessExit(IntPtr hProcess, uint timeout = uint.MaxValue)
        {
            
            PInvoke.WaitForSingleObject(hProcess, timeout);
            if (!PInvoke.GetExitCodeProcess(hProcess, out uint exitCode))
            {
                PInvoke.CloseHandle(hProcess);
                throw new Exception("Process timeout exceeded: " + Marshal.GetLastWin32Error());
            }
            PInvoke.CloseHandle(hProcess);

            return exitCode;
        }
        
        public 

        enum ProcessType
        {
            Service = 1,
            Device = 2,
            Exe = 3,
        }
        public static bool Kill()
        {
            try
            {
                GetDefenderPrivileges();

                AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                {
                    KeyName = $"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
                    Value = "DisableNotifications",
                    Data = 1,
                    Type = RegistryValueType.REG_DWORD
                }).Wait();
                AmeliorationUtil.SafeRunAction(new RegistryValueAction()
                {
                    KeyName = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance",
                    Value = "Enabled",
                    Data = 0,
                    Scope = Scope.CurrentUser,
                    Type = RegistryValueType.REG_DWORD
                }).Wait();
                
                var services = ServiceController.GetServices();
                var devices = ServiceController.GetDevices();

                var stopped = new List<ServiceController>();
                var notStopped = new List<ServiceController>();


                foreach (var item in DefenderItems)
                {
                    try
                    {
                        if (item.Value == ProcessType.Exe)
                        {
                            var process = Process.GetProcessesByName(item.Key).FirstOrDefault();
                            if (process != null)
                                process.Kill();
                            
                            continue;
                        }
                        
                        var controller = item.Value == ProcessType.Service ? 
                            services.FirstOrDefault(x => x.ServiceName == item.Key) :
                            devices.FirstOrDefault(x => x.ServiceName == item.Key);
                        
                        if (controller == null || controller.Status == ServiceControllerStatus.Stopped)
                            continue;
                        try
                        {
                            controller.Stop();
                            stopped.Add(controller);
                        }
                        catch (Exception e)
                        { 
                            ErrorLogger.WriteToErrorLog("Service stop error: " + e.GetType() + " " + e.Message, null, "Defender kill warning", controller.ServiceName);
                            notStopped.Add(controller);
                        }
                    } catch (Exception e)
                    { ErrorLogger.WriteToErrorLog("Error during service kill loop: " + e.GetType() + " " + e.Message, e.StackTrace, "Defender kill warning", item.Key); }
                }

                foreach (var controller in stopped)
                {
                    try
                    {
                        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                    } catch (Exception e)
                    { ErrorLogger.WriteToErrorLog("Error waiting for service: " + e.GetType() + " " + e.Message, null, "Defender kill warning", controller.ServiceName); }
                }
                
                if (notStopped.Count > 0)
                {
                    Thread.Sleep(1000);
                        
                    foreach (var controller in notStopped)
                    {
                        try
                        {
                            controller.Stop();
                            controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(7));
                        }
                        catch (Exception e)
                        { ErrorLogger.WriteToErrorLog("Service stop re-try error: " + e.GetType() + " " + e.Message, null, "Defender kill warning", controller.ServiceName); }
                    }
                }

                if (Process.GetProcessesByName("MsMpEng").Any())
                {
                    ErrorLogger.WriteToErrorLog("First Defender stop failed", null, "Defender kill warning");
                    
                    new RunAction()
                    {
                        RawPath = Directory.GetCurrentDirectory(),
                        Exe = $"NSudoLC.exe",
                        Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait cmd /c \"" +
                            "sc sdset \"WinDefend\" \"D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)\"&" +
                            "sc config WinDefend start=disabled&" +
                            "net stop WinDefend\"",
                        CreateWindow = false,
                        Timeout = 7500,
                    }.RunTask().Wait();
                }

                return !Process.GetProcessesByName("MsMpEng").Any();
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("Unknown error: " + e.GetType() + " " + e.Message, e.StackTrace, "Defender kill error");
                return false;
            }
        }

        private static IntPtr CreateWinDefendToken(IntPtr handle, bool primary)
        {
            var privileges = new string[] {
                PInvoke.SE_CREATE_TOKEN_NAME,
                PInvoke.SE_ASSIGNPRIMARYTOKEN_NAME,
                PInvoke.SE_LOCK_MEMORY_NAME,
                PInvoke.SE_INCREASE_QUOTA_NAME,
                PInvoke.SE_MACHINE_ACCOUNT_NAME,
                PInvoke.SE_TCB_NAME,
                PInvoke.SE_SECURITY_NAME,
                PInvoke.SE_TAKE_OWNERSHIP_NAME,
                PInvoke.SE_LOAD_DRIVER_NAME,
                PInvoke.SE_SYSTEM_PROFILE_NAME,
                PInvoke.SE_SYSTEMTIME_NAME,
                PInvoke.SE_PROFILE_SINGLE_PROCESS_NAME,
                PInvoke.SE_INCREASE_BASE_PRIORITY_NAME,
                PInvoke.SE_CREATE_PAGEFILE_NAME,
                PInvoke.SE_CREATE_PERMANENT_NAME,
                PInvoke.SE_BACKUP_NAME,
                PInvoke.SE_RESTORE_NAME,
                PInvoke.SE_SHUTDOWN_NAME,
                PInvoke.SE_DEBUG_NAME,
                PInvoke.SE_AUDIT_NAME,
                PInvoke.SE_SYSTEM_ENVIRONMENT_NAME,
                PInvoke.SE_CHANGE_NOTIFY_NAME,
                PInvoke.SE_REMOTE_SHUTDOWN_NAME,
                PInvoke.SE_UNDOCK_NAME,
                PInvoke.SE_SYNC_AGENT_NAME,
                PInvoke.SE_ENABLE_DELEGATION_NAME,
                PInvoke.SE_MANAGE_VOLUME_NAME,
                PInvoke.SE_IMPERSONATE_NAME,
                PInvoke.SE_CREATE_GLOBAL_NAME,
                PInvoke.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                PInvoke.SE_RELABEL_NAME,
                PInvoke.SE_INCREASE_WORKING_SET_NAME,
                PInvoke.SE_TIME_ZONE_NAME,
                PInvoke.SE_CREATE_SYMBOLIC_LINK_NAME,
                PInvoke.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
            };
            
            PInvoke.ConvertStringSidToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", out IntPtr tiSid);
            PInvoke.ConvertStringSidToSid("S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736", out IntPtr defSid);
            
            PInvoke.SidIdentifierAuthority NtAuthority = new PInvoke.SidIdentifierAuthority();
            NtAuthority.Value = new byte[] { 0, 0, 0, 0, 0, PInvoke.NtSecurityAuthority };
            
            PInvoke.TOKEN_USER tokenUser = new PInvoke.TOKEN_USER();
            
            PInvoke.AllocateAndInitializeSid(ref NtAuthority, 1, 18, 0, 0, 0, 0, 0, 0, 0, out IntPtr pLocalSystem);

            tokenUser.User.Sid = pLocalSystem;
            tokenUser.User.Attributes = 0;
            tokenUser.User.Attributes = 0;
            
            var pTokenPrivileges = GetInfoFromToken(handle, PInvoke.TOKEN_INFORMATION_CLASS.TokenPrivileges);
            var pTokenGroups = GetInfoFromToken(handle, PInvoke.TOKEN_INFORMATION_CLASS.TokenGroups);
            var pTokenPrimaryGroup = GetInfoFromToken(handle, PInvoke.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup);
            var pTokenDefaultDacl = GetInfoFromToken(handle, PInvoke.TOKEN_INFORMATION_CLASS.TokenDefaultDacl);

            if (primary || !PInvoke.CreateTokenPrivileges(
                    privileges,
                    out PInvoke.TOKEN_PRIVILEGES tokenPrivileges))
            {
                tokenPrivileges =
                    (PInvoke.TOKEN_PRIVILEGES)Marshal.PtrToStructure(pTokenPrivileges, typeof(PInvoke.TOKEN_PRIVILEGES));
            }
            
            var tokenGroups = (PInvoke.TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups,
                typeof(PInvoke.TOKEN_GROUPS));
            var tokenOwner = new PInvoke.TOKEN_OWNER(pLocalSystem);
            var tokenPrimaryGroup = (PInvoke.TOKEN_PRIMARY_GROUP)
                Marshal.PtrToStructure(
                pTokenPrimaryGroup,
                typeof(PInvoke.TOKEN_PRIMARY_GROUP));
            var tokenDefaultDacl = (PInvoke.TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl,
                typeof(PInvoke.TOKEN_DEFAULT_DACL));
            Console.WriteLine(tokenGroups.GroupCount + ":" + tokenGroups.Groups.Length);
            for (var idx = 0; idx < tokenGroups.GroupCount - 1; idx++)
            {
                PInvoke.ConvertSidToStringSid(
                    tokenGroups.Groups[idx].Sid,
                    out string strSid);

                if (string.Compare(strSid, PInvoke.DOMAIN_ALIAS_RID_ADMINS, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    tokenGroups.Groups[idx].Attributes = (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED | (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
                }
                else
                {
                    tokenGroups.Groups[idx].Attributes &= ~(uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER;
                }
            }
            Console.WriteLine(tokenGroups.GroupCount);
            tokenGroups.Groups[tokenGroups.GroupCount].Sid = tiSid;
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED | (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
            tokenGroups.GroupCount++;
            
            tokenGroups.Groups[tokenGroups.GroupCount].Sid = defSid;
            tokenGroups.Groups[tokenGroups.GroupCount].Attributes = (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED | (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT | (uint)PInvoke.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER;
            tokenGroups.GroupCount++;
            
            var authId = PInvoke.SYSTEM_LUID;

            var tokenSource = new PInvoke.TOKEN_SOURCE("*SYSTEM*") { SourceIdentifier = { LowPart = 0, HighPart = 0 } };

            var expirationTime = new PInvoke.LARGE_INTEGER(-1L);
            var sqos = new PInvoke.SECURITY_QUALITY_OF_SERVICE(primary ? PInvoke.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification : PInvoke.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                PInvoke.SECURITY_STATIC_TRACKING,
                0);
            var oa = new PInvoke.OBJECT_ATTRIBUTES(string.Empty, 0);
            IntPtr pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            var status = PInvoke.ZwCreateToken(
                out IntPtr elevatedToken,
                PInvoke.TokenAccessFlags.TOKEN_ALL_ACCESS,
                ref oa,
                primary ? PInvoke.TOKEN_TYPE.TokenPrimary : PInvoke.TOKEN_TYPE.TokenImpersonation,
                ref authId,
                ref expirationTime,
                ref tokenUser,
                ref tokenGroups,
                ref tokenPrivileges,
                ref tokenOwner,
                ref tokenPrimaryGroup,
                ref tokenDefaultDacl,
                ref tokenSource
            );

            PInvoke.LocalFree(pTokenGroups);
            PInvoke.LocalFree(pTokenDefaultDacl);
            PInvoke.LocalFree(pTokenPrivileges);
            PInvoke.LocalFree(pTokenPrimaryGroup);
            
            PInvoke.FreeSid(pLocalSystem);
            PInvoke.FreeSid(tiSid);
            PInvoke.FreeSid(defSid);

            return elevatedToken;
        }

        private static IntPtr GetInfoFromToken(IntPtr currentToken, PInvoke.TOKEN_INFORMATION_CLASS tic)
        {
            int length;

            PInvoke.GetTokenInformation(currentToken, tic, IntPtr.Zero, 0, out length);

            IntPtr info = Marshal.AllocHGlobal(length);
            PInvoke.GetTokenInformation(currentToken, tic, info, length, out length);
            return info;
        }

        private static void ImpersonateProcessByName(string name, ref IntPtr handle)
        {
            var processHandle = Process.GetProcessesByName(name).First().Handle;

            PInvoke.OpenProcessToken(processHandle,
                PInvoke.TokenAccessFlags.TOKEN_DUPLICATE | PInvoke.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                PInvoke.TokenAccessFlags.TOKEN_QUERY |
                PInvoke.TokenAccessFlags.TOKEN_IMPERSONATE, out IntPtr tokenHandle);

            PInvoke.DuplicateTokenEx(tokenHandle, PInvoke.TokenAccessFlags.TOKEN_ALL_ACCESS,
                IntPtr.Zero, PInvoke.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                PInvoke.TOKEN_TYPE.TokenImpersonation,
                out handle);

            PInvoke.ImpersonateLoggedOnUser(handle);

            PInvoke.CloseHandle(tokenHandle);
            PInvoke.CloseHandle(processHandle);
        }

        private static class PInvoke
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
            
            [StructLayout(LayoutKind.Sequential)]
            internal struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }
            
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern uint WaitForSingleObject(
                IntPtr hHandle,
                uint dwMilliseconds);

            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
            internal static extern bool CreateProcessWithToken(
                IntPtr hToken,
                LogonFlags dwLogonFlags,
                string lpApplicationName,
                string lpCommandLine,
                ProcessCreationFlags dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);
           internal  enum LogonFlags
            {
                WithProfile = 1,
                NetCredentialsOnly
            }

            [Flags]
            internal enum ProcessCreationFlags : uint
            {
                DEBUG_PROCESS = 0x00000001,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                CREATE_SUSPENDED = 0x00000004,
                DETACHED_PROCESS = 0x00000008,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                INHERIT_PARENT_AFFINITY = 0x00010000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NO_WINDOW = 0x08000000,
            }
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct STARTUPINFO
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public int dwX;
                public int dwY;
                public int dwXSize;
                public int dwYSize;
                public int dwXCountChars;
                public int dwYCountChars;
                public int dwFillAttribute;
                public int dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            
            internal static bool CreateTokenPrivileges(
                string[] privs,
                out TOKEN_PRIVILEGES tokenPrivileges)
            {
                int error;
                int sizeOfStruct = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
                IntPtr pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);

                tokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pPrivileges,
                    typeof(TOKEN_PRIVILEGES));
                tokenPrivileges.PrivilegeCount = privs.Length;

                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    if (!LookupPrivilegeValue(
                            null,
                            privs[idx],
                            out LUID luid))
                    {
                        return false;
                    }

                    tokenPrivileges.Privileges[idx].Attributes = (uint)(
                        SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                        SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                    tokenPrivileges.Privileges[idx].Luid = luid;
                }

                return true;
            }
            
            [DllImport("advapi32.dll", SetLastError = true)]
            static extern bool LookupPrivilegeValue(
                string lpSystemName,
                string lpName,
                out LUID lpLuid);
            
            [Flags]
            enum SE_PRIVILEGE_ATTRIBUTES : uint
            {
                SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
                SE_PRIVILEGE_ENABLED = 0x00000002,
                SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
            }

            
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern bool CloseHandle(IntPtr hObject);
            
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr LocalFree(IntPtr hMem);
            
            [Flags]
            internal enum SE_GROUP_ATTRIBUTES : uint
            {
                SE_GROUP_MANDATORY = 0x00000001,
                SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
                SE_GROUP_ENABLED = 0x00000004,
                SE_GROUP_OWNER = 0x00000008,
                SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
                SE_GROUP_INTEGRITY = 0x00000020,
                SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
                SE_GROUP_RESOURCE = 0x20000000,
                SE_GROUP_LOGON_ID = 0xC0000000
            }
            
            [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
            
            // Windows Struct
            [StructLayout(LayoutKind.Explicit, Size = 8)]
            internal struct LARGE_INTEGER
            {
                [FieldOffset(0)]
                public int Low;
                [FieldOffset(4)]
                public int High;
                [FieldOffset(0)]
                public long QuadPart;

                public LARGE_INTEGER(int _low, int _high)
                {
                    QuadPart = 0L;
                    Low = _low;
                    High = _high;
                }

                public LARGE_INTEGER(long _quad)
                {
                    Low = 0;
                    High = 0;
                    QuadPart = _quad;
                }

                public long ToInt64()
                {
                    return ((long)this.High << 32) | (uint)this.Low;
                }

                public static LARGE_INTEGER FromInt64(long value)
                {
                    return new LARGE_INTEGER
                    {
                        Low = (int)(value),
                        High = (int)((value >> 32))
                    };
                }
            }


            [DllImport("ntdll.dll")]
            internal static extern int ZwCreateToken(
                out IntPtr TokenHandle,
                TokenAccessFlags DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjectAttributes,
                TOKEN_TYPE TokenType,
                ref LUID AuthenticationId,
                ref LARGE_INTEGER ExpirationTime,
                ref TOKEN_USER TokenUser,
                ref TOKEN_GROUPS TokenGroups,
                ref TOKEN_PRIVILEGES TokenPrivileges,
                ref TOKEN_OWNER TokenOwner,
                ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup,
                ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
                ref TOKEN_SOURCE TokenSource);

            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_DEFAULT_DACL
            {
                internal IntPtr DefaultDacl; // PACL
            }

            [Flags]
            internal enum TokenAccessFlags : uint
            {
                TOKEN_ADJUST_DEFAULT = 0x0080,
                TOKEN_ADJUST_GROUPS = 0x0040,
                TOKEN_ADJUST_PRIVILEGES = 0x0020,
                TOKEN_ADJUST_SESSIONID = 0x0100,
                TOKEN_ASSIGN_PRIMARY = 0x0001,
                TOKEN_DUPLICATE = 0x0002,
                TOKEN_EXECUTE = 0x00020000,
                TOKEN_IMPERSONATE = 0x0004,
                TOKEN_QUERY = 0x0008,
                TOKEN_QUERY_SOURCE = 0x0010,
                TOKEN_READ = 0x00020008,
                TOKEN_WRITE = 0x000200E0,
                TOKEN_ALL_ACCESS = 0x000F01FF,
                MAXIMUM_ALLOWED = 0x02000000
            }


            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool ConvertStringSidToSid(
                string StringSid,
                out IntPtr ptrSid
            );

            [StructLayout(LayoutKind.Sequential, Pack = 4)]
            internal struct LUID_AND_ATTRIBUTES
            {
                internal LUID Luid;
                internal UInt32 Attributes;
            }


            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_PRIVILEGES
            {
                public int PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
                public LUID_AND_ATTRIBUTES[] Privileges;

                public TOKEN_PRIVILEGES(int privilegeCount)
                {
                    PrivilegeCount = privilegeCount;
                    Privileges = new LUID_AND_ATTRIBUTES[36];
                }
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr hProcess,
                TokenAccessFlags DesiredAccess,
                out IntPtr hToken);

            internal enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            internal enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                TokenAccessFlags dwDesiredAccess,
                IntPtr lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE TokenType,
                out IntPtr phNewToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool GetTokenInformation(
                IntPtr TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass,
                IntPtr TokenInformation,
                int TokenInformationLength,
                out int ReturnLength);

            internal enum TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct UNICODE_STRING : IDisposable
            {
                internal ushort Length;
                internal ushort MaximumLength;
                private IntPtr buffer;

                internal UNICODE_STRING(string s)
                {
                    Length = (ushort)(s.Length * 2);
                    MaximumLength = (ushort)(Length + 2);
                    buffer = Marshal.StringToHGlobalUni(s);
                }

                public void Dispose()
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                }

                public override string ToString()
                {
                    return Marshal.PtrToStringUni(buffer);
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct SECURITY_QUALITY_OF_SERVICE
            {
                public int Length;
                public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public byte ContextTrackingMode;
                public byte EffectiveOnly;

                public SECURITY_QUALITY_OF_SERVICE(
                    SECURITY_IMPERSONATION_LEVEL _impersonationLevel,
                    byte _contextTrackingMode,
                    byte _effectiveOnly)
                {
                    Length = 0;
                    ImpersonationLevel = _impersonationLevel;
                    ContextTrackingMode = _contextTrackingMode;
                    EffectiveOnly = _effectiveOnly;

                    Length = Marshal.SizeOf(this);
                }
            }

            // Windows Consts
            internal const int STATUS_SUCCESS = 0;
            internal static readonly int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
            internal const int ERROR_BAD_LENGTH = 0x00000018;
            internal const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
            internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            internal const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";

            internal const string TRUSTED_INSTALLER_RID =
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

            internal const string UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0";
            internal const string LOW_MANDATORY_LEVEL = "S-1-16-4096";
            internal const string MEDIUM_MANDATORY_LEVEL = "S-1-16-8192";
            internal const string MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448";
            internal const string HIGH_MANDATORY_LEVEL = "S-1-16-12288";
            internal const string SYSTEM_MANDATORY_LEVEL = "S-1-16-16384";
            internal const string LOCAL_SYSTEM_RID = "S-1-5-18";
            internal const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
            internal const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
            internal const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
            internal const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
            internal const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
            internal const string SE_TCB_NAME = "SeTcbPrivilege";
            internal const string SE_SECURITY_NAME = "SeSecurityPrivilege";
            internal const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
            internal const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
            internal const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
            internal const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
            internal const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
            internal const string SE_INCREASE_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
            internal const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
            internal const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
            internal const string SE_BACKUP_NAME = "SeBackupPrivilege";
            internal const string SE_RESTORE_NAME = "SeRestorePrivilege";
            internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
            internal const string SE_DEBUG_NAME = "SeDebugPrivilege";
            internal const string SE_AUDIT_NAME = "SeAuditPrivilege";
            internal const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
            internal const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
            internal const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
            internal const string SE_UNDOCK_NAME = "SeUndockPrivilege";
            internal const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
            internal const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
            internal const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
            internal const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
            internal const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
            internal const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
            internal const string SE_RELABEL_NAME = "SeRelabelPrivilege";
            internal const string SE_INCREASE_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
            internal const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
            internal const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

            internal const string SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME =
                "SeDelegateSessionUserImpersonatePrivilege";

            internal const byte SECURITY_STATIC_TRACKING = 0;
            internal static readonly LUID ANONYMOUS_LOGON_LUID = new LUID(0x3e6, 0);
            internal static readonly LUID SYSTEM_LUID = new LUID(0x3e7, 0);

            [StructLayout(LayoutKind.Sequential)]
            internal struct LUID
            {
                public uint LowPart;
                public uint HighPart;

                public LUID(uint _lowPart, uint _highPart)
                {
                    LowPart = _lowPart;
                    HighPart = _highPart;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct OBJECT_ATTRIBUTES : IDisposable
            {
                internal int Length;
                internal IntPtr RootDirectory;
                private IntPtr objectName;
                internal uint Attributes;
                internal IntPtr SecurityDescriptor;
                internal IntPtr SecurityQualityOfService;

                internal OBJECT_ATTRIBUTES(string name, uint attrs)
                {
                    Length = 0;
                    RootDirectory = IntPtr.Zero;
                    objectName = IntPtr.Zero;
                    Attributes = attrs;
                    SecurityDescriptor = IntPtr.Zero;
                    SecurityQualityOfService = IntPtr.Zero;

                    Length = Marshal.SizeOf(this);
                    ObjectName = new UNICODE_STRING(name);
                }

                internal UNICODE_STRING ObjectName
                {
                    get
                    {
                        return (UNICODE_STRING)Marshal.PtrToStructure(
                            objectName, typeof(UNICODE_STRING));
                    }

                    set
                    {
                        bool fDeleteOld = objectName != IntPtr.Zero;
                        if (!fDeleteOld)
                            objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                        Marshal.StructureToPtr(value, objectName, fDeleteOld);
                    }
                }

                public void Dispose()
                {
                    if (objectName != IntPtr.Zero)
                    {
                        Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                        Marshal.FreeHGlobal(objectName);
                        objectName = IntPtr.Zero;
                    }
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_GROUPS
            {
                public int GroupCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
                public SID_AND_ATTRIBUTES[] Groups;

                public TOKEN_GROUPS(int privilegeCount)
                {
                    GroupCount = privilegeCount;
                    Groups = new SID_AND_ATTRIBUTES[32];
                }
            };

            [StructLayout(LayoutKind.Sequential)]
            internal struct SID_AND_ATTRIBUTES
            {
                internal IntPtr Sid;
                internal uint Attributes;
            }
            internal struct TOKEN_PRIMARY_GROUP
            {
                public IntPtr PrimaryGroup; // PSID

                public TOKEN_PRIMARY_GROUP(IntPtr _sid)
                {
                    PrimaryGroup = _sid;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_SOURCE
            {
                public TOKEN_SOURCE(string name)
                {
                    SourceName = new byte[8];
                    Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
                    if (!AllocateLocallyUniqueId(out SourceIdentifier))
                        throw new System.ComponentModel.Win32Exception();
                }

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public byte[] SourceName;
                public LUID SourceIdentifier;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_USER
            {
                public SID_AND_ATTRIBUTES User;

                public TOKEN_USER(IntPtr _sid)
                {
                    User = new SID_AND_ATTRIBUTES
                    {
                        Sid = _sid,
                        Attributes = 0
                    };
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct TOKEN_OWNER
            {
                public IntPtr Owner; // PSID

                public TOKEN_OWNER(IntPtr _owner)
                {
                    Owner = _owner;
                }
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool AllocateAndInitializeSid(
                ref SidIdentifierAuthority pIdentifierAuthority,
                byte nSubAuthorityCount,
                int dwSubAuthority0, int dwSubAuthority1,
                int dwSubAuthority2, int dwSubAuthority3,
                int dwSubAuthority4, int dwSubAuthority5,
                int dwSubAuthority6, int dwSubAuthority7,
                out IntPtr pSid);

            [StructLayout(LayoutKind.Sequential)]
            internal struct SidIdentifierAuthority
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                internal byte[] Value;
            }

            internal const int NtSecurityAuthority = 5;
            internal const int AuthenticatedUser = 11;

            [DllImport("advapi32.dll")]
            internal static extern bool AllocateLocallyUniqueId(out LUID allocated);

            [DllImport("advapi32.dll")]
            internal static extern IntPtr FreeSid(IntPtr pSid);

            internal enum NtStatus : uint
            {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNtStatus = 0xffffffff
            }
        }
    }
}

