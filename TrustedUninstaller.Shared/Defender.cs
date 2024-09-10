using System.IO;
using System.Windows;
using Core.Actions;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Core;
using Interprocess;
using JetBrains.Annotations;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32.TaskScheduler;

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
                    Log.EnqueueSafe(LogType.Info, "PASS: " + file, new SerializableTrace());
                }
                catch (Exception e)
                {
                    Log.EnqueueExceptionSafe(e, file);
                }
            }
        }
        
        [InterprocessMethod(Level.Administrator)]
        private static bool DisableDefenderPrivileged()
        {
            try
            {
                Defender.Disable();
            }
            catch (Exception ex)
            {
                Log.WriteExceptionSafe(ex, $"First Defender disable failed from second process.");

                Defender.Kill();
                try
                {
                    Defender.Disable();
                }
                catch (Exception e)
                {
                    Log.WriteExceptionSafe(e, $"Could not disable Windows Defender from second process.");
                    throw;
                }
            }
            return true;
        }
        
        [InterprocessMethod(Level.Administrator)]
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
                    Log.WriteExceptionSafe(e, "Error renaming files in Defender directory.", ("Directory", defenderDir));
                }
            }
        }

        [InterprocessMethod(Level.Administrator)]
        public static void DeCripple()
        {
            if (!DisableDefenderPrivileged())
                Log.EnqueueSafe(LogType.Error, "Defender disable after restart failed.", new SerializableTrace());
            
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
        
        [InterprocessMethod(Level.Administrator)]
        public static void DisableBlocklist(InterLink.InterProgress progress, InterLink.InterMessageReporter reporter, bool UCPD)
        {
            if (UCPD)
                DisableUCPD(null);
            
            progress.Report(10);
            Thread.Sleep(250);
            
            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First memory integrity disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"" /v Enabled /d 0 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable memory integrity.", new SerializableTrace());
            }
            
            progress.Report(60);
            Thread.Sleep(250);
            
            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First blocklist disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"" /v VulnerableDriverBlocklistEnable /d 0 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable blocklist.", new SerializableTrace());
            }
            
            progress.Report(100);
        }
        
        [InterprocessMethod(Level.Administrator)]
        public static void DisableUCPD([CanBeNull] InterLink.InterProgress progress)
        {

            try
            {
                using (TaskService ts = new TaskService())
                {
                    var task = ts.GetTask(@"\Microsoft\Windows\AppxDeploymentClient\UCPD velocity");
                    if (task != null)
                    {
                        task.Definition.Settings.Enabled = false;
                        task.Enabled = false;
                        task.RegisterChanges();
                    }
                }
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "Failed to disable UCPD task.");
            }
            
            if (progress != null)
            {
                progress.Report(10);
                Thread.Sleep(250);
            }
            
            try
            {
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\UCPD", Value = "Start", Data = 4, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\UCPD", Value = "Start", Data = 4, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First memory integrity disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Services\UCPD"" /v Start /d 4 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\UCPD", Value = "Start", Data = 4, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable memory integrity.", new SerializableTrace());
            }
            
            if (progress != null)
            {
                progress.Report(80);
                Thread.Sleep(250);
                progress.Report(100);
            }
        }

        [InterprocessMethod(Level.Administrator)]
        public static bool KillAndDisable(InterLink.InterProgress progress, InterLink.InterMessageReporter reporter, bool forceSafeBoot, bool noSafeBoot)
        {
            try
            {
                if (!forceSafeBoot)
                {
                    Thread.Sleep(250);
                    reporter.Report("Disabling UCPD...");
                    DisableUCPD(null);
                    Thread.Sleep(350);
                    progress.Report(2);
                    reporter.Report("Extracting service package...");
                    string cabPath = null;

                    cabPath = ExtractCab();
                    progress.Report(4);

                    reporter.Report("Adding certificate...");
                    var certPath = Path.GetTempFileName();

                    int exitCode;
                    exitCode = RunPSCommand(
                        $"try {{" +
                        $"$cert = (Get-AuthenticodeSignature '{cabPath}').SignerCertificate; " +
                        $"[System.IO.File]::WriteAllBytes('{certPath}', $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)); " +
                        $"Import-Certificate '{certPath}' -CertStoreLocation 'Cert:\\LocalMachine\\Root' | Out-Null; " +
                        $"Copy-Item -Path \"HKLM:\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\$($cert.Thumbprint)\" \"HKLM:\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\8A334AA8052DD244A647306A76B8178FA215F344\" -Force | Out-Null; " +
                        $"EXIT 0; " +
                        $"}} catch {{EXIT 1}}", null, null);

                    Thread.Sleep(250);

                    if (exitCode == 1)
                        throw new Exception("Could not add certificate.");

                    progress.Report(10);

                    reporter.Report("Applying service package...");
                    string err = null;

                    decimal lastProgress = 10;
                    double lastDismProgress = 0;
                    exitCode = RunCommand("DISM.exe",
                        $"/Online /Add-Package /PackagePath:\"{cabPath}\" /NoRestart /IgnoreCheck",
                        (sender, args) =>
                        {
                            if (args.Data != null && args.Data.Contains("%"))
                            {
                                int i = args.Data.IndexOf('%') - 1;
                                while (args.Data[i] == '.' || Char.IsDigit(args.Data[i])) i--;
                                if (double.TryParse(args.Data.Substring(i + 1, args.Data.IndexOf('%') - i - 1), out double dismProgress))
                                {
                                    if (lastDismProgress == dismProgress)
                                        return;
                                    lastProgress = (decimal)((dismProgress / 100) * 80) + 10;
                                    progress.Report(lastProgress);
                                    lastDismProgress = dismProgress;
                                }
                            }
                        },
                        ((sender, args) =>
                        {
                            if (err == null && args.Data != null)
                                err = args.Data;
                            else if (err != null && args.Data != null)
                                err = err + Environment.NewLine + args.Data;
                        }));

                    if (exitCode != 0 && exitCode != 3010)
                    {
                        if (noSafeBoot)
                        {
                            Console.WriteLine("\r\nDefender removal package application failed. Please restart and try again.");
                            Environment.Exit(1);
                            return false;
                        }
                        
                        Log.EnqueueSafe(LogType.Info, "Live dism application failed: " + err, new SerializableTrace(), ("Exit code", exitCode));

                        reporter.Report("Removing certificate...");
                        exitCode = RunPSCommand(
                            $"$cert = (Get-AuthenticodeSignature '{cabPath}').SignerCertificate; " +
                            $"Get-ChildItem 'Cert:\\LocalMachine\\Root\\$($cert.Thumbprint)' | Remove-Item -Force | Out-Null; " +
                            $"Remove-Item \"HKLM:\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\8A334AA8052DD244A647306A76B8178FA215F344\" -Force -Recurse | Out-Null"
                            , null, null);

                        progress.Report(lastProgress + 5);

                        reporter.Report("Adding service...");
                        InstallService();
                        Thread.Sleep(2000);

                        progress.Report(95);

                        reporter.Report("Enabling SafeBoot...");
                        RunCommand("bcdedit.exe", "/set {current} safeboot minimal", null, null);
                        Thread.Sleep(500);

                        progress.Report(100);

                        return false;
                    }

                    progress.Report(90);

                    reporter.Report("Removing certificate...");
                    exitCode = RunPSCommand(
                        $"$cert = (Get-AuthenticodeSignature '{cabPath}').SignerCertificate; " +
                        $"Get-ChildItem 'Cert:\\LocalMachine\\Root\\$($cert.Thumbprint)' | Remove-Item -Force | Out-Null; " +
                        $"Remove-Item \"HKLM:\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\8A334AA8052DD244A647306A76B8178FA215F344\" -Force -Recurse | Out-Null"
                        , null, null);
                    
                    try { File.Delete(cabPath); }
                    catch
                    {
                    }

                    progress.Report(100);

                    return true;
                }
                else
                {
                    Thread.Sleep(250);
                    progress.Report(2);
                    reporter.Report("Disabling UCPD...");
                    DisableUCPD(null);
                    Thread.Sleep(350);
                    progress.Report(4);

                    reporter.Report("Adding service...");
                    Thread.Sleep(500);
                    progress.Report(10);
                    InstallService();
                    Thread.Sleep(1000);
                    progress.Report(25);
                    Thread.Sleep(1200);
                    progress.Report(50);
                    Thread.Sleep(1300);
                    progress.Report(70);

                    reporter.Report("Enabling SafeBoot...");
                    RunCommand("bcdedit.exe", "/set {current} safeboot minimal", null, null);
                    Thread.Sleep(2000);

                    progress.Report(100);

                    return false;
                }
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e);
                throw;
            }
        }

        private static void InstallService()
        {
            bool displayLastUsername = EnableDontDisplayLastUsername();
            
            IntPtr scm = Win32.Service.OpenSCManager(null, null, Win32.Service.SCM_ACCESS.SC_MANAGER_CREATE_SERVICE);
            if (scm == IntPtr.Zero)
                throw new ApplicationException("Could not connect to service control manager.");

            try
            {
                IntPtr service = Win32.Service.OpenService(scm, "AMEPrepare", Win32.Service.SERVICE_ACCESS.SERVICE_DELETE);
                if (service != IntPtr.Zero)
                    UninstallService(service);
                    
                service = Win32.Service.CreateService(scm, "AMEPrepare", "AME Prepare", Win32.Service.ServiceAccessRights.AllAccess, Win32.Service.SERVICE_WIN32_OWN_PROCESS, Win32.Service.ServiceBootFlag.AutoStart, Win32.Service.ServiceError.Normal, 
                    $"\"{Win32.ProcessEx.GetCurrentProcessFileLocation()}\" -Service {displayLastUsername}", null, IntPtr.Zero, null, null, null);

                if (service == IntPtr.Zero)
                    throw new ApplicationException("Failed to install service.");
                
                AllowServiceSafeBoot();

                Win32.Service.CloseServiceHandle(service);
            }
            finally
            {
                Win32.Service.CloseServiceHandle(scm);
            }
        }
        
        private static bool EnableDontDisplayLastUsername()
        {
            var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true);
            if (key != null)
            {
                var value = key.GetValue("dontdisplaylastusername");
        
                if (value is int intValue && intValue == 1)
                {
                    return true;
                }
        
                key.SetValue("dontdisplaylastusername", 1, RegistryValueKind.DWord);
            }

            return false;
        }
        private static void AllowServiceSafeBoot()
        {
            var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal", true);
            if (key != null)
            {
                var subKey = key.CreateSubKey("AMEPrepare");
                subKey?.SetValue("", "Service", RegistryValueKind.String);
            }
        }
        
        public static void UninstallService(IntPtr service)
        {
            Win32.Service.SERVICE_STATUS status = new Win32.Service.SERVICE_STATUS();
            Win32.Service.ControlService(service, Win32.Service.ServiceControl.Stop, status);
            var changedStatus = WaitForServiceStatus(service, Win32.Service.ServiceState.StopPending, Win32.Service.ServiceState.Stopped);
            if (!changedStatus)
                throw new ApplicationException("Unable to stop service");

            if (!Win32.Service.DeleteService(service))
                throw new ApplicationException("Could not delete service " + Marshal.GetLastWin32Error());
            else
                Win32.Service.CloseServiceHandle(service);
        }
        
        private static bool WaitForServiceStatus(IntPtr service, Win32.Service.ServiceState waitStatus, Win32.Service.ServiceState desiredStatus)
        {
            Win32.Service.SERVICE_STATUS status = new Win32.Service.SERVICE_STATUS();

            Win32.Service.QueryServiceStatus(service, status);
            if (status.dwCurrentState == desiredStatus) return true;

            int dwStartTickCount = Environment.TickCount;
            int dwOldCheckPoint = status.dwCheckPoint;

            while (status.dwCurrentState == waitStatus)
            {
                // Do not wait longer than the wait hint. A good interval is
                // one tenth the wait hint, but no less than 1 second and no
                // more than 10 seconds.

                int dwWaitTime = status.dwWaitHint / 10;

                if (dwWaitTime < 1000) dwWaitTime = 1000;
                else if (dwWaitTime > 10000) dwWaitTime = 10000;

                Thread.Sleep(dwWaitTime);

                // Check the status again.

                if (Win32.Service.QueryServiceStatus(service, status) == 0) break;

                if (status.dwCheckPoint > dwOldCheckPoint)
                {
                    // The service is making progress.
                    dwStartTickCount = Environment.TickCount;
                    dwOldCheckPoint = status.dwCheckPoint;
                }
                else
                {
                    if (Environment.TickCount - dwStartTickCount > status.dwWaitHint)
                    {
                        // No progress made within the wait hint
                        break;
                    }
                }
            }
            return (status.dwCurrentState == desiredStatus || status.dwCurrentState == Win32.Service.ServiceState.NotFound);
        }

        private static int RunPSCommand(string command, [CanBeNull] DataReceivedEventHandler outputHandler, [CanBeNull] DataReceivedEventHandler errorHandler) =>
            RunCommand("powershell.exe", $"-NoP -C \"{command}\"", outputHandler, errorHandler);
        private static int RunCommand(string exe, string arguments, [CanBeNull] DataReceivedEventHandler outputHandler, [CanBeNull] DataReceivedEventHandler errorHandler)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo()
                {
                    FileName = exe,
                    Arguments = arguments,

                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = outputHandler != null,
                    RedirectStandardError = errorHandler != null
                }
            };

            if (outputHandler != null)
                process.OutputDataReceived += outputHandler;
            if (errorHandler != null)
                process.ErrorDataReceived += errorHandler;

            process.Start();
            
            if (outputHandler != null)
                process.BeginOutputReadLine();
            if (errorHandler != null)
                process.BeginErrorReadLine();

            process.WaitForExit();
            return process.ExitCode;
        }

        private static string ExtractCab()
        {
            var cabArch = Win32.SystemInfoEx.SystemArchitecture == Architecture.Arm || Win32.SystemInfoEx.SystemArchitecture == Architecture.Arm64 ? "arm64" : "amd64";
            
            var fileDir = Environment.ExpandEnvironmentVariables("%ProgramData%\\AME");
            if (!Directory.Exists(fileDir)) Directory.CreateDirectory(fileDir);

            var destination = Path.Combine(fileDir, $"Z-AME-NoDefender-Package31bf3856ad364e35{cabArch}1.0.0.0.cab");
            
            if (File.Exists(destination))
            {
                return destination;
            }
            
            Assembly assembly = Assembly.GetEntryAssembly();
            using (UnmanagedMemoryStream stream = (UnmanagedMemoryStream)assembly!.GetManifestResourceStream($"TrustedUninstaller.GUI.Resources.Z-AME-NoDefender-Package31bf3856ad364e35{cabArch}1.0.0.0.cab"))
            {
                byte[] buffer = new byte[stream!.Length];
                stream.Read(buffer, 0, buffer.Length);
                File.WriteAllBytes(destination, buffer);
            }
            return destination;
        }
        
        [InterprocessMethod(Level.Administrator)]
        public static bool Disable()
        {
            bool restartRequired = true;

            foreach (var service in DefenderItems.Where(x => x.Value == ProcessType.Service || x.Value == ProcessType.Device).Select(x => x.Key))
            {
                CoreActions.SafeRun(new RegistryValueAction()
                    { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + service, Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD, Operation = RegistryValueOperation.Set });
            }
            
            CoreActions.SafeRun(new RegistryValueAction()
                { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD });
            CoreActions.SafeRun(new RegistryValueAction()
                { KeyName = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", Value = "EnableSmartScreen", Data = 0, Type = RegistryValueType.REG_DWORD });

            try
            {
                new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "ProductAppDataPath", Operation = RegistryValueOperation.Delete }.RunTask();
                new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "InstallLocation", Operation = RegistryValueOperation.Delete }.RunTask();
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "Error removing Defender install values.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait cmd /c \"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\" /v \"ProductAppDataPath\" /f &" +
                        " reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\" /v \"InstallLocation\" /f\"",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender", Value = "InstallLocation", Operation = RegistryValueOperation.Delete }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Could not remove defender install values.");
            }

            try
            {
                new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.RunTask();

                if (new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {

                Log.EnqueueExceptionSafe(e, "First WinDefend service removal failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryKeyAction() { KeyName = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                {
                    Log.EnqueueSafe(LogType.Warning, "WinDefend service removal failed.", new SerializableTrace());

                    try
                    {
                        new RegistryValueAction()
                            { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.RunTask();

                        if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.GetStatus() !=
                            UninstallTaskStatus.Completed)
                            throw new Exception("Unknown reason");
                    }
                    catch (Exception ex)
                    {
                        Log.EnqueueExceptionSafe(e, "First WinDefend disable failed.");

                        new RunAction()
                        {
                            RawPath = Directory.GetCurrentDirectory(),
                            Exe = $"NSudoLC.exe",
                            Arguments = "-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d 4 /f",
                            CreateWindow = false
                        }.RunTask();

                        if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend", Value = "Start", Data = 4, Type = RegistryValueType.REG_DWORD }.GetStatus() !=
                            UninstallTaskStatus.Completed)
                            throw new Exception("Could not disable WinDefend service.");
                    }
                }
            }

            try
            {
                // MpOAV.dll is normally in use by a lot of processes. This prevents that.
                new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.RunTask();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First MpOAV mapping removal failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments = @"-U:T -P:E -M:S -Priority:RealTime -ShowWindowMode:Hide -Wait reg delete ""HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32"" /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not remove MpOAV mapping.", new SerializableTrace());
            }

            try
            {
                // smartscreenps.dll is sometimes in use by a lot of processes. This prevents that.
                new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.RunTask();

                // This may not be important.
                new RegistryKeyAction() { KeyName = @"HKCR\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.RunTask();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.AppReputationService" }.RunTask();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.EventLogger" }.RunTask();
                new RegistryKeyAction() { KeyName = @"HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Internal.Security.SmartScreen.UriReputationService" }.RunTask();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    throw new Exception("Unknown reason");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First smartscreenps mapping removal failed.");

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
                }.RunTask();

                if (new RegistryKeyAction() { KeyName = @"HKCR\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}\InprocServer32" }.GetStatus() !=
                    UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not remove smartscreenps mapping.", new SerializableTrace());
            }


            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First memory integrity disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"" /v Enabled /d 0 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable memory integrity.", new SerializableTrace());
            }
            
            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First memory integrity disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"" /v Enabled /d 0 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", Value = "Enabled", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable memory integrity.", new SerializableTrace());
            }

            try
            {
                // Can cause ProcessHacker driver warnings without this
                new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    throw new Exception("Unknown error");
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "First blocklist disable failed.");

                new RunAction()
                {
                    RawPath = Directory.GetCurrentDirectory(),
                    Exe = $"NSudoLC.exe",
                    Arguments =
                        @"-U:T -P:E -M:S -ShowWindowMode:Hide -Priority:RealTime -Wait reg add ""HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"" /v VulnerableDriverBlocklistEnable /d 0 /f",
                    CreateWindow = false
                }.RunTask();

                if (new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", Value = "VulnerableDriverBlocklistEnable", Data = 0, }.GetStatus()
                    != UninstallTaskStatus.Completed)
                    Log.EnqueueSafe(LogType.Warning, "Could not disable blocklist.", new SerializableTrace());
            }

            return restartRequired;
        }

        public static void GetDefenderPrivileges()
        {
            ImpersonateProcessByName("winlogon", out Win32.TokensEx.SafeTokenHandle impersonatedTokenHandle);
            impersonatedTokenHandle.Dispose();

            ImpersonateProcessByName("lsass", out impersonatedTokenHandle);

            impersonatedTokenHandle = CreateWinDefendToken(impersonatedTokenHandle, false);

            Win32.Tokens.ImpersonateLoggedOnUser(impersonatedTokenHandle);
        }
        
        [InterprocessMethod(Level.Administrator)]
        public static int StartElevatedProcess(string exe, string command)
        {
            ImpersonateProcessByName("winlogon", out Win32.TokensEx.SafeTokenHandle impersonatedTokenHandle);
            impersonatedTokenHandle.Dispose();

            ImpersonateProcessByName("lsass", out impersonatedTokenHandle);

            impersonatedTokenHandle = CreateWinDefendToken(impersonatedTokenHandle, true);

            var process = new AugmentedProcess.Process();
            process.StartInfo = new AugmentedProcess.ProcessStartInfo(exe, command) { UseShellExecute = false, CreateNoWindow = true };
            process.Start(AugmentedProcess.Process.CreateType.UserToken, ref impersonatedTokenHandle);
            
            return process!.Id;
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

                CoreActions.SafeRun(new RegistryValueAction()
                {
                    KeyName = $"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications",
                    Value = "DisableNotifications",
                    Data = 1,
                    Type = RegistryValueType.REG_DWORD
                });
                CoreActions.SafeRun(new RegistryValueAction()
                {
                    KeyName = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance",
                    Value = "Enabled",
                    Data = 0,
                    Type = RegistryValueType.REG_DWORD
                });
                
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
                            Log.EnqueueExceptionSafe(e, "Service stop error.");
                            notStopped.Add(controller);
                        }
                    } catch (Exception e)
                    { Log.EnqueueExceptionSafe(e, "Error during service kill loop."); }
                }

                foreach (var controller in stopped)
                {
                    try
                    {
                        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                    } catch (Exception e)
                    { Log.EnqueueExceptionSafe(e, "Error waiting for service."); }
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
                        { Log.EnqueueExceptionSafe(e, "Service stop re-try error."); }
                    }
                }

                if (Process.GetProcessesByName("MsMpEng").Any())
                {
                    Log.EnqueueSafe(LogType.Warning, "First Defender stop failed.", new SerializableTrace());
                    
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
                    }.RunTask();
                }

                return !Process.GetProcessesByName("MsMpEng").Any();
            }
            catch (Exception e)
            {
                Log.EnqueueExceptionSafe(e, "Unknown error.");
                return false;
            }
        }

        private static Win32.TokensEx.SafeTokenHandle CreateWinDefendToken(Win32.TokensEx.SafeTokenHandle handle, bool primary)
        {
            Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_ASSIGNPRIMARYTOKEN_NAME);
            Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_INCREASE_QUOTA_NAME);

            var privileges = new[]
            {
                Win32.Tokens.SE_INCREASE_QUOTA_NAME,
                Win32.Tokens.SE_MACHINE_ACCOUNT_NAME,
                Win32.Tokens.SE_SECURITY_NAME,
                Win32.Tokens.SE_TAKE_OWNERSHIP_NAME,
                Win32.Tokens.SE_LOAD_DRIVER_NAME,
                Win32.Tokens.SE_SYSTEM_PROFILE_NAME,
                Win32.Tokens.SE_SYSTEMTIME_NAME,
                Win32.Tokens.SE_PROFILE_SINGLE_PROCESS_NAME,
                Win32.Tokens.SE_INCREASE_BASE_PRIORITY_NAME,
                Win32.Tokens.SE_CREATE_PERMANENT_NAME,
                Win32.Tokens.SE_BACKUP_NAME,
                Win32.Tokens.SE_RESTORE_NAME,
                Win32.Tokens.SE_SHUTDOWN_NAME,
                Win32.Tokens.SE_DEBUG_NAME,
                Win32.Tokens.SE_AUDIT_NAME,
                Win32.Tokens.SE_SYSTEM_ENVIRONMENT_NAME,
                Win32.Tokens.SE_CHANGE_NOTIFY_NAME,
                Win32.Tokens.SE_UNDOCK_NAME,
                Win32.Tokens.SE_SYNC_AGENT_NAME,
                Win32.Tokens.SE_ENABLE_DELEGATION_NAME,
                Win32.Tokens.SE_MANAGE_VOLUME_NAME,
                Win32.Tokens.SE_IMPERSONATE_NAME,
                Win32.Tokens.SE_CREATE_GLOBAL_NAME,
                Win32.Tokens.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                Win32.Tokens.SE_RELABEL_NAME,
                Win32.Tokens.SE_TIME_ZONE_NAME,
                Win32.Tokens.SE_CREATE_SYMBOLIC_LINK_NAME,
                Win32.Tokens.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
                Win32.Tokens.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32.Tokens.SE_REMOTE_SHUTDOWN_NAME,
                Win32.Tokens.SE_INCREASE_WORKING_SET_NAME,
                Win32.Tokens.SE_TCB_NAME,
                Win32.Tokens.SE_CREATE_PAGEFILE_NAME,
                Win32.Tokens.SE_LOCK_MEMORY_NAME,
                Win32.Tokens.SE_CREATE_TOKEN_NAME
            };
            var authId = Win32.Tokens.SYSTEM_LUID;
            
            Win32.SID.SID_IDENTIFIER_AUTHORITY ntAuthority = new Win32.SID.SID_IDENTIFIER_AUTHORITY();
            ntAuthority.Value = new byte[] { 0, 0, 0, 0, 0, Win32.SID.NtSecurityAuthority };
            
            Win32.SID.AllocateAndInitializeSid(ref ntAuthority, 1, 18, 0, 0, 0, 0, 0, 0, 0, out Win32.SID.SafeSIDHandle pLocalSystem);

            Win32.Tokens.TOKEN_USER tokenUser = new Win32.Tokens.TOKEN_USER();
            tokenUser.User.Sid = pLocalSystem.DangerousGetHandle();
            tokenUser.User.Attributes = 0;

            var pTokenPrivileges =
                Win32.TokensEx.GetInfoFromToken(handle, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenPrivileges, Marshal.SizeOf<Win32.Tokens.TOKEN_PRIVILEGES>());
            var pTokenGroups =
                Win32.TokensEx.GetInfoFromToken(handle, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenGroups, Marshal.SizeOf<Win32.Tokens.TOKEN_GROUPS>());
            var pTokenPrimaryGroup =
                Win32.TokensEx.GetInfoFromToken(handle, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, Marshal.SizeOf<Win32.Tokens.TOKEN_PRIMARY_GROUP>());
            var pTokenDefaultDacl =
                Win32.TokensEx.GetInfoFromToken(handle, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenDefaultDacl, Marshal.SizeOf<Win32.Tokens.TOKEN_DEFAULT_DACL>());

            var tokenPrivileges = Win32.TokensEx.CreateTokenPrivileges(privileges);
            var tokenGroups = (Win32.Tokens.TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups, typeof(Win32.Tokens.TOKEN_GROUPS));
            var tokenPrimaryGroup =
                (Win32.Tokens.TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(pTokenPrimaryGroup,
                    typeof(Win32.Tokens.TOKEN_PRIMARY_GROUP));
            var tokenDefaultDacl = (Win32.Tokens.TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl, typeof(Win32.Tokens.TOKEN_DEFAULT_DACL));
            
            var tokenOwner = new Win32.Tokens.TOKEN_OWNER(pLocalSystem.DangerousGetHandle());
            var tokenSource = new Win32.Tokens.TOKEN_SOURCE("*SYSTEM*") { SourceIdentifier = { LowPart = 0, HighPart = 0 } };

            List<string> requiredGroups = new List<string>()
            {
                Win32.SID.DOMAIN_ALIAS_RID_ADMINS,
                Win32.SID.DOMAIN_ALIAS_RID_LOCAL_AND_ADMIN_GROUP,
                Win32.SID.TRUSTED_INSTALLER_RID,
                Win32.SID.NT_SERVICE_SID,
                "S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736"
            };
            List<Win32.SID.SafeSIDHandle> requiredSids = new List<Win32.SID.SafeSIDHandle>();
            
            for (var idx = 0; idx < tokenGroups.GroupCount - 1; idx++)
            {
                Win32.SID.ConvertSidToStringSid(tokenGroups.Groups[idx].Sid, out string strSid);
                foreach (var requiredGroup in requiredGroups.ToArray())
                {
                    if (string.Compare(strSid, requiredGroup, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        tokenGroups.Groups[idx].Attributes &= ~(uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_USE_FOR_DENY_ONLY;
                        tokenGroups.Groups[idx].Attributes |= 
                            (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                            (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                            (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER;
                        requiredGroups.Remove(requiredGroup);
                    }
                }
            }
            
            foreach (var requiredGroup in requiredGroups)
            {
                Win32.SID.ConvertStringSidToSid(requiredGroup, out Win32.SID.SafeSIDHandle sid);
                if (sid.IsInvalid)
                    Log.EnqueueSafe(LogType.Warning, "Could not convert string SID to SID: " + requiredGroup, new SerializableTrace());
                else
                {
                    requiredSids.Add(sid);
                    tokenGroups.Groups[tokenGroups.GroupCount].Sid = sid.DangerousGetHandle();
                    tokenGroups.Groups[tokenGroups.GroupCount].Attributes =
                        (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                        (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT |
                        (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER;
                    tokenGroups.GroupCount++;
                }
            }

            var expirationTime = new Win32.LARGE_INTEGER() { QuadPart = -1L };
            var sqos = new Win32.Tokens.SECURITY_QUALITY_OF_SERVICE(
                Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, Win32.Tokens.SECURITY_STATIC_TRACKING,
                0);
            var oa = new Win32.Tokens.OBJECT_ATTRIBUTES(string.Empty, 0) { };
            var pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            var status = Win32.Tokens.ZwCreateToken(out Win32.TokensEx.SafeTokenHandle elevatedToken,
                Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, ref oa, Win32.Tokens.TOKEN_TYPE.TokenPrimary,
                ref authId, ref expirationTime, ref tokenUser, ref tokenGroups, ref tokenPrivileges, ref tokenOwner,
                ref tokenPrimaryGroup, ref tokenDefaultDacl, ref tokenSource);

            Win32.LocalFree(pTokenGroups);
            Win32.LocalFree(pTokenDefaultDacl);
            Win32.LocalFree(pTokenPrivileges);
            Win32.LocalFree(pTokenPrimaryGroup);

            requiredSids.ForEach(x => x.Dispose());
            pLocalSystem.Dispose();

            if (status != 0)
                throw new Win32Exception($"Error creating defender token: " + status);

            var sessionId = Process.GetCurrentProcess().SessionId;
            if (!Win32.Tokens.SetTokenInformation(elevatedToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(int)))
                throw new Win32Exception("Error setting token session id: " + Marshal.GetLastWin32Error());

            return elevatedToken;
        }

        private static void ImpersonateProcessByName(string name, out Win32.TokensEx.SafeTokenHandle handle)
        {
            using var process = Process.GetProcessesByName(name).First();
            var processHandle = new SafeProcessHandle(process.Handle, false);

            Win32.Tokens.OpenProcessToken(processHandle,
                Win32.Tokens.TokenAccessFlags.TOKEN_DUPLICATE | Win32.Tokens.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                Win32.Tokens.TokenAccessFlags.TOKEN_QUERY |
                Win32.Tokens.TokenAccessFlags.TOKEN_IMPERSONATE, out Win32.TokensEx.SafeTokenHandle tokenHandle);

            Win32.Tokens.DuplicateTokenEx(tokenHandle, Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS,
                IntPtr.Zero, Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                Win32.Tokens.TOKEN_TYPE.TokenImpersonation,
                out handle);

            if (!Win32.Tokens.ImpersonateLoggedOnUser(handle))
                throw new Win32Exception("Error impersonating token: " + Marshal.GetLastWin32Error());

            tokenHandle.Dispose();
        }
    }
}