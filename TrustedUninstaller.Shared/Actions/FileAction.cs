using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using Core;

namespace TrustedUninstaller.Shared.Actions
{
    public class FileAction : Tasks.TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        [YamlMember(typeof(string), Alias = "path")]
        public string RawPath { get; set; }
        
        [YamlMember(typeof(string), Alias = "prioritizeExe")]
        public bool ExeFirst { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 2;
        
        [YamlMember(typeof(string), Alias = "useNSudoTI")]
        public bool TrustedInstaller { get; set; } = false;

        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => true;
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        

        public string ErrorString() => $"FileAction failed to remove file or directory '{Environment.ExpandEnvironmentVariables(RawPath)}'.";

        private string GetRealPath()
        {
            return Environment.ExpandEnvironmentVariables(RawPath);
        }

        private string GetRealPath(string path)
        {
            return Environment.ExpandEnvironmentVariables(path);
        }

        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            if (InProgress) return UninstallTaskStatus.InProgress; var realPath = GetRealPath();
            
            if (realPath.Contains("*"))
            {
                var lastToken = realPath.LastIndexOf("\\");
                var parentPath = realPath.Remove(lastToken).TrimEnd('\\');

                // This is to prevent it from re-iterating with an incorrect argument
                if (parentPath.Contains("*")) return UninstallTaskStatus.Completed;
                var filter = realPath.Substring(lastToken + 1);

                if (Directory.Exists(parentPath) && (Directory.GetFiles(parentPath, filter).Any() || Directory.GetDirectories(parentPath, filter).Any()))
                {
                    return UninstallTaskStatus.ToDo;
                } 
                else return UninstallTaskStatus.Completed;
            }
            
            var isFile = File.Exists(realPath);
            var isDirectory = Directory.Exists(realPath);

            return isFile || isDirectory ? UninstallTaskStatus.ToDo : UninstallTaskStatus.Completed;
        }
        
        [DllImport("Unlocker.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private static extern bool EzUnlockFileW(string path);
        
        private async Task DeleteFile(string file, Output.OutputWriter output, bool log = false)
        {
            if (!TrustedInstaller)
            {
                try { File.Delete(file);} catch (Exception e) { }
                    
                if (File.Exists(file))
                {
                    try
                    {
                        EzUnlockFileW(file);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                    }
                    
                    try { await Task.Run(() => File.Delete(file)); }
                    catch (Exception e)
                    {
                        //Testing.WriteLine(e, "DeleteFile > File.Delete(File)");
                    }
                    CmdAction delAction = new CmdAction()
                    {
                        Command = $"del /q /f \"{file}\""
                    };
                    delAction.RunTaskOnMainThread(output);
                }
            }
            else if (File.Exists("NSudoLC.exe"))
            {
                try
                {
                    var result = EzUnlockFileW(file);
                   //Testing.WriteLine($"ExUnlock on ({file}) result: " + result); 
                }
                catch (Exception e)
                {
                    Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                }                
                RunAction tiDelAction = new RunAction()
                {
                    Exe = "NSudoLC.exe",
                    Arguments = $"-U:T -P:E -M:S -Priority:RealTime -UseCurrentConsole -Wait cmd /c \"del /q /f \"{file}\"\"",
                    BaseDir = true,
                    CreateWindow = false
                };

                tiDelAction.RunTaskOnMainThread(output);
            }
            else
            {
                Log.WriteSafe(LogType.Warning, "NSudo was invoked with no supplied NSudo executable.", new SerializableTrace(), output.LogOptions);
            }
        }
        private async Task RemoveDirectory(string dir, Output.OutputWriter output, bool log = false)
        {
            if (!TrustedInstaller)
            {
                try { Directory.Delete(dir, true); } catch { }
                    
                if (Directory.Exists(dir))
                {
                    output.WriteLineSafe("Info", "Directory still exists.. trying second method.");
                    var deleteDirCmd = new CmdAction()
                    {
                        Command = $"rmdir /Q /S \"{dir}\""
                    };
                    deleteDirCmd.RunTaskOnMainThread(output);
                }
            }
            else if (File.Exists("NSudoLC.exe"))
            {
                RunAction tiDelAction = new RunAction()
                {
                    Exe = "NSudoLC.exe",
                    Arguments = $"-U:T -P:E -M:S -Priority:RealTime -UseCurrentConsole -Wait cmd /c \"rmdir /q /s \"{dir}\"\"",
                    BaseDir = true,
                    CreateWindow = false
                };
                
                tiDelAction.RunTaskOnMainThread(output);
            }
            else
            {
                Log.WriteSafe(LogType.Warning, "NSudo was invoked with no supplied NSudo executable.", new SerializableTrace(), output.LogOptions);
            }
        }
        private async Task DeleteItemsInDirectory(string dir, Output.OutputWriter output, string filter = "*")
        {
            var realPath = GetRealPath(dir);

            var files = Directory.EnumerateFiles(realPath, filter);
            var directories = Directory.EnumerateDirectories(realPath, filter);
            
            if (ExeFirst) files = files.ToList().OrderByDescending(x => x.EndsWith(".exe"));

            var lockedFilesList = new List<string> { "MpOAV.dll", "MsMpLics.dll", "EppManifest.dll", "MpAsDesc.dll", "MpClient.dll", "MsMpEng.exe" };
            foreach (var file in files)
            {
                output.WriteLineSafe("Info", $"Deleting {file}...");

                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await DeleteFile(file, output);

                if (File.Exists(file))
                {
                    TaskKillAction taskKillAction = new TaskKillAction();

                    if (file.EndsWith(".sys"))
                    {
                        var driverService = Path.GetFileNameWithoutExtension(file);
                        try
                        {
                            //ServiceAction won't work here due to it not being able to detect driver services.
                            var cmdAction = new CmdAction();
                            output.WriteLineSafe("Info", $"Removing driver service {driverService}...");

                            // TODO: Replace with win32
                            try
                            {
                                ServiceInstaller ServiceInstallerObj = new ServiceInstaller();
                                ServiceInstallerObj.Context = new InstallContext();
                                ServiceInstallerObj.ServiceName = driverService; 
                                ServiceInstallerObj.Uninstall(null);
                            }
                            catch (Exception e)
                            {
                                Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                            }
                                
                            cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop" :
                                $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop";
                            if (AmeliorationUtil.UseKernelDriver) cmdAction.RunTaskOnMainThread(output);

                            cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete" :
                                $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete";
                            if (AmeliorationUtil.UseKernelDriver) cmdAction.RunTaskOnMainThread(output);
                        }
                        catch (Exception servException)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, servException, output.LogOptions);
                        }
                    }
                    if (lockedFilesList.Contains(Path.GetFileName(file)))
                    {
                        TaskKillAction killAction = new TaskKillAction()
                        {
                            ProcessName = "MsMpEng"
                        };

                        await killAction.RunTask(output);

                        killAction.ProcessName = "NisSrv";
                        await killAction.RunTask(output);

                        killAction.ProcessName = "SecurityHealthService";
                        await killAction.RunTask(output);

                        killAction.ProcessName = "smartscreen";
                        await killAction.RunTask(output);

                    }

                    var processes = new List<Process>();
                    try
                    {
                        processes = WinUtil.WhoIsLocking(file);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                    }

                    var delay = 0;

                    int svcCount = 0;
                    foreach (var svchost in processes.Where(x => x.ProcessName.Equals("svchost")))
                    {
                        try
                        {
                            foreach (var serviceName in Win32.ServiceEx.GetServicesFromProcessId(svchost.Id))
                            {
                                svcCount++;
                                try
                                {
                                    var serviceController = ServiceController.GetServices().FirstOrDefault(x => x.ServiceName.Equals(serviceName));
                                    if (serviceController != null)
                                        svcCount += serviceController.DependentServices.Length;
                                }
                                catch (Exception e)
                                {
                                    output.WriteLineSafe("Info", $"\r\nError: Could not get amount of dependent services for {serviceName}.\r\nException: " + e.Message);
                                }
                            }
                        } catch (Exception e)
                        {
                            output.WriteLineSafe("Info", $"\r\nError: Could not get amount of services locking file.\r\nException: " + e.Message);
                        }
                    }
                    
                    while (processes.Any() && delay <= 800)
                    {
                        output.WriteLineSafe("Info", "Processes locking the file:");
                        foreach (var process in processes)
                        {
                            output.WriteLineSafe("Info", process.ProcessName);
                        }
                        if (svcCount > 10)
                        {
                            output.WriteLineSafe("Info", "Amount of locking services exceeds 10, skipping...");
                            break;
                        }

                        foreach (var process in processes)
                        {
                            try
                            {
                                if (process.ProcessName.Equals("TrustedUninstaller.CLI"))
                                {
                                    output.WriteLineSafe("Info", "Skipping TU.CLI...");
                                    continue;
                                }
                                if (Regex.Match(process.ProcessName, "ame.?wizard", RegexOptions.IgnoreCase).Success)
                                {
                                    output.WriteLineSafe("Info", "Skipping AME Wizard...");
                                    continue;
                                }

                                taskKillAction.ProcessName = process.ProcessName;
                                taskKillAction.ProcessID = process.Id;

                                output.WriteLineSafe("Info", $"Killing locking process {process.ProcessName} with PID {process.Id}...");
                            }
                            catch (InvalidOperationException)
                            {
                                // Calling ProcessName on a process object that has exited will thrown this exception causing the
                                // entire loop to abort. Since killing a process takes a bit of time, another process in the loop
                                // could exit during that time. This accounts for that.
                                continue;
                            }

                            try
                            {
                                await taskKillAction.RunTask(output);
                            }
                            catch (Exception e)
                            {
                                Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                            }
                        }

                        // This gives any obstinant processes some time to unlock the file on their own.
                        //
                        // This could be done above but it's likely to cause HasExited errors if delays are
                        // introduced after WhoIsLocking.
                        System.Threading.Thread.Sleep(delay);
                        
                        try
                        {
                            processes = WinUtil.WhoIsLocking(file);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                        }
                        
                        delay += 100;
                    }
                    if (delay >= 800)
                        Log.WriteSafe(LogType.Warning, "Could not kill locking processes for file '{file}'. Process termination loop exceeded max cycles (8).", new SerializableTrace(), output.LogOptions);
                    
                    if (Path.GetExtension(file).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        await new TaskKillAction() { ProcessName = Path.GetFileNameWithoutExtension(file) }.RunTask(output);
                    }

                    await DeleteFile(file, output, true);
                }
            }
            //Loop through any subdirectories
            foreach (var directory in directories)
            {
                //Deletes the content of the directory
                await DeleteItemsInDirectory(directory, output);

                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await RemoveDirectory(directory, output, true);

                if (Directory.Exists(directory))
                    Log.WriteSafe(LogType.Warning, $"Could not remove directory '{directory}'.", new SerializableTrace(), output.LogOptions);
            }
        }

        public async Task<bool> RunTask(Output.OutputWriter output)
        {
            if (InProgress) throw new TaskInProgressException("Another File action was called while one was in progress.");
            InProgress = true;

            var realPath = GetRealPath();
            
            output.WriteLineSafe("Info", $"Removing file or directory '{realPath}'...");
            
            if (realPath.Contains("*"))
            {
                var lastToken = realPath.LastIndexOf("\\");
                var parentPath = realPath.Remove(lastToken).TrimEnd('\\');

                if (parentPath.Contains("*")) throw new ArgumentException("Parent directories to a given file filter cannot contain wildcards.");
                var filter = realPath.Substring(lastToken + 1);

                await DeleteItemsInDirectory(parentPath, output, filter);
                
                InProgress = false;
                return true;
            }
            
            var isFile = File.Exists(realPath);
            var isDirectory = Directory.Exists(realPath);
            
            if (isDirectory)
            {
                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await RemoveDirectory(realPath, output);

                if (Directory.Exists(realPath))
                {
                    CmdAction permAction = new CmdAction()
                    {
                        Command = $"takeown /f \"{realPath}\" /r /d Y>NUL & icacls \"{realPath}\" /t /grant Administrators:F /c > NUL",
                        Timeout = 5000
                    };
                    try
                    {
                        permAction.RunTaskOnMainThread(output);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                    }

                    try
                    {
                        if (realPath.Contains("Defender"))
                        {
                            TaskKillAction killAction = new TaskKillAction()
                            {
                                ProcessName = "MsMpEng"
                            };

                            await killAction.RunTask(output);

                            killAction.ProcessName = "NisSrv";
                            await killAction.RunTask(output);

                            killAction.ProcessName = "SecurityHealthService";
                            await killAction.RunTask(output);

                            killAction.ProcessName = "smartscreen";
                            await killAction.RunTask(output);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                    }
                    
                    await RemoveDirectory(realPath, output, true);

                    if (Directory.Exists(realPath))
                    {
                        //Delete the files in the initial directory. DOES delete directories.
                        await DeleteItemsInDirectory(realPath, output);

                        System.GC.Collect();
                        System.GC.WaitForPendingFinalizers();
                        await RemoveDirectory(realPath, output, true);
                    }
                }
            }
            if (isFile)
            {
                try
                {
                    var lockedFilesList = new List<string> { "MpOAV.dll", "MsMpLics.dll", "EppManifest.dll", "MpAsDesc.dll", "MpClient.dll", "MsMpEng.exe" };
                    var fileName = realPath.Split('\\').LastOrDefault();

                    
                    System.GC.Collect();
                    System.GC.WaitForPendingFinalizers();

                    await DeleteFile(realPath, output);

                    if (File.Exists(realPath))
                    {
                        CmdAction permAction = new CmdAction()
                        {
                            Command = $"takeown /f \"{realPath}\" /r /d Y>NUL & icacls \"{realPath}\" /t /grant Administrators:F /c > NUL",
                            Timeout = 5000
                        };
                        try
                        {
                            permAction.RunTaskOnMainThread(output);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                        }
                        
                        TaskKillAction taskKillAction = new TaskKillAction();

                        if (realPath.EndsWith(".sys"))
                        {
                            var driverService = Path.GetFileNameWithoutExtension(realPath);
                            try
                            {
                                //ServiceAction won't work here due to it not being able to detect driver services.
                                var cmdAction = new CmdAction();
                                output.WriteLineSafe("Info", $"Removing driver service {driverService}...");

                                // TODO: Replace with win32
                                try
                                {
                                    ServiceInstaller ServiceInstallerObj = new ServiceInstaller();
                                    ServiceInstallerObj.Context = new InstallContext();
                                    ServiceInstallerObj.ServiceName = driverService; 
                                    ServiceInstallerObj.Uninstall(null);
                                }
                                catch (Exception e)
                                {
                                    Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                                }
                                
                                WinUtil.CheckKph();
                                
                                cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                    $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop" :
                                    $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop";
                                if (AmeliorationUtil.UseKernelDriver) cmdAction.RunTaskOnMainThread(output);

                                cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                    $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete" :
                                    $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete";
                                if (AmeliorationUtil.UseKernelDriver) cmdAction.RunTaskOnMainThread(output);
                            }
                            catch (Exception servException)
                            {
                                Log.WriteExceptionSafe(LogType.Warning, servException, output.LogOptions);
                            }
                        }

                        if (lockedFilesList.Contains(fileName))
                        {
                            TaskKillAction killAction = new TaskKillAction()
                            {
                                ProcessName = "MsMpEng"
                            };

                            await killAction.RunTask(output);

                            killAction.ProcessName = "NisSrv";
                            await killAction.RunTask(output);

                            killAction.ProcessName = "SecurityHealthService";
                            await killAction.RunTask(output);

                            killAction.ProcessName = "smartscreen";
                            await killAction.RunTask(output);

                        }

                        var processes = new List<Process>();
                        try
                        {
                            processes = WinUtil.WhoIsLocking(realPath);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                        }
                        var delay = 0;

                        int svcCount = 0;
                        foreach (var svchost in processes.Where(x => x.ProcessName.Equals("svchost")))
                        {
                            try
                            {
                                foreach (var serviceName in Win32.ServiceEx.GetServicesFromProcessId(svchost.Id))
                                {
                                    svcCount++;
                                    try
                                    {
                                        var serviceController = ServiceController.GetServices().FirstOrDefault(x => x.ServiceName.Equals(serviceName));
                                        if (serviceController != null)
                                            svcCount += serviceController.DependentServices.Length;
                                    }
                                    catch (Exception e)
                                    {
                                        output.WriteLineSafe("Warning", $"\r\nError: Could not get amount of dependent services for {serviceName}.\r\nException: " + e.Message);
                                    }
                                }
                            } catch (Exception e)
                            {
                                output.WriteLineSafe("Warning", $"\r\nError: Could not get amount of services locking file.\r\nException: " + e.Message);
                            }
                        }
                        if (svcCount > 8) output.WriteLineSafe("Info", "Amount of locking services exceeds 8, skipping...");
                        
                        while (processes.Any() && delay <= 800 && svcCount <= 8)
                        {
                            output.WriteLineSafe("Info", "Processes locking the file:");
                            foreach (var process in processes)
                            {
                                output.WriteLineSafe("Info", process.ProcessName);
                            }

                            foreach (var process in processes)
                            {
                                try
                                {
                                    if (process.ProcessName.Equals("TrustedUninstaller.CLI"))
                                    {
                                        output.WriteLineSafe("Info", "Skipping TU.CLI...");
                                        continue;
                                    }
                                    if (Regex.Match(process.ProcessName, "ame.?wizard", RegexOptions.IgnoreCase).Success)
                                    {
                                        output.WriteLineSafe("Info", "Skipping AME Wizard...");
                                        continue;
                                    }

                                    taskKillAction.ProcessName = process.ProcessName;
                                    taskKillAction.ProcessID = process.Id;

                                    output.WriteLineSafe("Info", $"Killing {process.ProcessName} with PID {process.Id}... it is locking {realPath}");
                                }
                                catch (InvalidOperationException)
                                {
                                    // Calling ProcessName on a process object that has exited will thrown this exception causing the
                                    // entire loop to abort. Since killing a process takes a bit of time, another process in the loop
                                    // could exit during that time. This accounts for that.
                                    continue;
                                }

                                try
                                {
                                    await taskKillAction.RunTask(output);
                                }
                                catch (Exception e)
                                {
                                    Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                                }
                            }

                            // This gives any obstinant processes some time to unlock the file on their own.
                            //
                            // This could be done above but it's likely to cause HasExited errors if delays are
                            // introduced after WhoIsLocking.
                            System.Threading.Thread.Sleep(delay);
                        
                            try
                            {
                                processes = WinUtil.WhoIsLocking(realPath);
                            }
                            catch (Exception e)
                            {
                                Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                            }
                        
                            delay += 100;
                        }
                        if (delay >= 800)
                            Log.WriteSafe(LogType.Warning, "Could not kill locking processes for file '{realPath}'. Process termination loop exceeded max cycles (8).", new SerializableTrace(), output.LogOptions);

                        if (Path.GetExtension(realPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            await new TaskKillAction() { ProcessName = Path.GetFileNameWithoutExtension(realPath) }.RunTask(output);
                        }
                        
                        await DeleteFile(realPath, output, true);
                    }
                }
                catch (Exception e)
                {
                    Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                }
            }
            else
            {
                output.WriteLineSafe("Info", $"File or directory '{realPath}' not found.");
            }

            InProgress = false;
            return true;
        }
    }
}