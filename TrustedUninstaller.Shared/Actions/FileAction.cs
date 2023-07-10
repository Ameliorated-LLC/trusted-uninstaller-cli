using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class FileAction : TaskAction, ITaskAction
    {
        [YamlMember(typeof(string), Alias = "path")]
        public string RawPath { get; set; }
        
        [YamlMember(typeof(string), Alias = "prioritizeExe")]
        public bool ExeFirst { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 2;
        
        [YamlMember(typeof(string), Alias = "useNSudoTI")]
        public bool TrustedInstaller { get; set; } = false;

        public int GetProgressWeight() => ProgressWeight;
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

        public UninstallTaskStatus GetStatus()
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
        
        private async Task DeleteFile(string file, bool log = false)
        {
            if (!TrustedInstaller)
            {
                try {await Task.Run(() => File.Delete(file));} catch {}
                    
                if (File.Exists(file))
                {
                    try
                    {
                        EzUnlockFileW(file);
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog($"Error while unlocking file: " + e.Message, e.StackTrace,
                            $"FileAction Error", file);
                    }
                    
                    try {await Task.Run(() => File.Delete(file));} catch {}
                    
                    CmdAction delAction = new CmdAction()
                    {
                        Command = $"del /q /f \"{file}\""
                    };
                    await delAction.RunTask();
                }
            }
            else if (File.Exists("NSudoLC.exe"))
            {
                try
                {
                    EzUnlockFileW(file);
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog($"Error while unlocking file: " + e.Message, e.StackTrace,
                        $"FileAction Error", file);
                }                
                RunAction tiDelAction = new RunAction()
                {
                    Exe = "NSudoLC.exe",
                    Arguments = $"-U:T -P:E -M:S -Priority:RealTime -UseCurrentConsole -Wait cmd /c \"del /q /f \"{file}\"\"",
                    BaseDir = true,
                    CreateWindow = false
                };

                await tiDelAction.RunTask();
                if (tiDelAction.Output != null)
                {
                    if (log) ErrorLogger.WriteToErrorLog(tiDelAction.Output, Environment.StackTrace,
                        $"FileAction Error", file);
                }
            }
            else
            {
                ErrorLogger.WriteToErrorLog($"NSudo was invoked with no supplied NSudo executable.", Environment.StackTrace,
                    $"FileAction Error", file);
            }
        }
        private async Task RemoveDirectory(string dir, bool log = false)
        {
            if (!TrustedInstaller)
            {
                try { Directory.Delete(dir, true); } catch { }
                    
                if (Directory.Exists(dir))
                {
                    Console.WriteLine("Directory still exists.. trying second method.");
                    var deleteDirCmd = new CmdAction()
                    {
                        Command = $"rmdir /Q /S \"{dir}\""
                    };
                    await deleteDirCmd.RunTask();
                        
                    if (deleteDirCmd.StandardError != null)
                    {
                        Console.WriteLine($"Error Output: {deleteDirCmd.StandardError}");
                    }
                    if (deleteDirCmd.StandardOutput != null)
                    {
                        Console.WriteLine($"Standard Output: {deleteDirCmd.StandardOutput}");
                    }
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
                
                await tiDelAction.RunTask();
                
                if (tiDelAction.Output != null)
                {
                    if (log) ErrorLogger.WriteToErrorLog(tiDelAction.Output, Environment.StackTrace,
                        $"FileAction Error", dir);
                }
            }
            else
            {
                ErrorLogger.WriteToErrorLog($"NSudo was invoked with no supplied NSudo executable.", Environment.StackTrace,
                    $"FileAction Error", dir);
            }
        }
        private async Task DeleteItemsInDirectory(string dir, string filter = "*")
        {
            var realPath = GetRealPath(dir);

            var files = Directory.EnumerateFiles(realPath, filter);
            var directories = Directory.EnumerateDirectories(realPath, filter);
            
            if (ExeFirst) files = files.ToList().OrderByDescending(x => x.EndsWith(".exe"));

            var lockedFilesList = new List<string> { "MpOAV.dll", "MsMpLics.dll", "EppManifest.dll", "MpAsDesc.dll", "MpClient.dll", "MsMpEng.exe" };
            foreach (var file in files)
            {
                Console.WriteLine($"Deleting {file}...");

                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await DeleteFile(file);

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
                            Console.WriteLine($"Removing driver service {driverService}...");

                            cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop" :
                                $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop";
                            await cmdAction.RunTask();

                            cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete" :
                                $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete";
                            await cmdAction.RunTask();
                        }
                        catch (Exception servException)
                        {
                            ErrorLogger.WriteToErrorLog(servException.Message, servException.StackTrace,
                                $"FileAction Error: Error while trying to delete driver service {driverService}.", file);
                        }
                    }
                    if (lockedFilesList.Contains(Path.GetFileName(file)))
                    {
                        TaskKillAction killAction = new TaskKillAction()
                        {
                            ProcessName = "MsMpEng"
                        };

                        await killAction.RunTask();

                        killAction.ProcessName = "NisSrv";
                        await killAction.RunTask();

                        killAction.ProcessName = "SecurityHealthService";
                        await killAction.RunTask();

                        killAction.ProcessName = "smartscreen";
                        await killAction.RunTask();

                    }

                    var processes = new List<Process>();
                    try
                    {
                        processes = WinUtil.WhoIsLocking(file);
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                            $"FileAction Error", file);
                    }

                    var delay = 0;

                    int svcCount = 0;
                    foreach (var svchost in processes.Where(x => x.ProcessName.Equals("svchost")))
                    {
                        try
                        {
                            using var search = new ManagementObjectSearcher($"select * from Win32_Service where ProcessId = '{svchost.Id}'");

                            foreach (ManagementObject queryObj in search.Get())
                            {
                                var serviceName = (string)queryObj["Name"]; // Access service name  
                                
                                var serv = ServiceController.GetServices().FirstOrDefault(x => x.ServiceName.Equals(serviceName));

                                if (serv == null) svcCount++;
                                else svcCount += serv.DependentServices.Length + 1;
                            }
                        } catch (Exception e)
                        {
                            Console.WriteLine($"\r\nError: Could not get amount of services locking file.\r\nException: " + e.Message);
                        }
                    }
                    
                    while (processes.Any() && delay <= 800)
                    {
                        Console.WriteLine("Processes locking the file:");
                        foreach (var process in processes)
                        {
                            Console.WriteLine(process.ProcessName);
                        }
                        if (svcCount > 10)
                        {
                            Console.WriteLine("Amount of locking services exceeds 10, skipping...");
                            break;
                        }

                        foreach (var process in processes)
                        {
                            try
                            {
                                if (process.ProcessName.Equals("TrustedUninstaller.CLI"))
                                {
                                    Console.WriteLine("Skipping TU.CLI...");
                                    continue;
                                }
                                if (Regex.Match(process.ProcessName, "ame.?wizard", RegexOptions.IgnoreCase).Success)
                                {
                                    Console.WriteLine("Skipping AME Wizard...");
                                    continue;
                                }

                                taskKillAction.ProcessName = process.ProcessName;
                                taskKillAction.ProcessID = process.Id;

                                Console.WriteLine($"Killing locking process {process.ProcessName} with PID {process.Id}...");
                            }
                            catch (InvalidOperationException)
                            {
                                // Calling ProcessName on a process object that has exited will thrown this exception causing the
                                // entire loop to abort. Since killing a process takes a bit of time, another process in the loop
                                // could exit during that time. This accounts for that.
                                continue;
                            }

                            await taskKillAction.RunTask();
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
                            ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                                $"FileAction Error", file);
                        }
                        
                        delay += 100;
                    }
                    if (delay >= 800)
                        ErrorLogger.WriteToErrorLog($"Could not kill locking processes for file '{file}'. Process termination loop exceeded max cycles (8).",
                            Environment.StackTrace, "FileAction Error");

                    await DeleteFile(file, true);

                    using (var writer = new StreamWriter("Logs\\FileChecklist.txt", true))
                    {
                        writer.WriteLine($"File Path: {file}\r\nDeleted: {!File.Exists(file)}\r\n" +
                            $"======================");
                    }
                }
            }
            //Loop through any subdirectories
            foreach (var directory in directories)
            {
                //Deletes the content of the directory
                await DeleteItemsInDirectory(directory);

                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await RemoveDirectory(directory, true);

                if (Directory.Exists(directory))
                    ErrorLogger.WriteToErrorLog($"Could not remove directory '{directory}'.",
                        Environment.StackTrace, $"FileAction Error");
            }
        }

        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another File action was called while one was in progress.");
            InProgress = true;

            var realPath = GetRealPath();
            
            Console.WriteLine($"Removing file or directory '{realPath}'...");
            
            if (realPath.Contains("*"))
            {
                var lastToken = realPath.LastIndexOf("\\");
                var parentPath = realPath.Remove(lastToken).TrimEnd('\\');

                if (parentPath.Contains("*")) throw new ArgumentException("Parent directories to a given file filter cannot contain wildcards.");
                var filter = realPath.Substring(lastToken + 1);

                await DeleteItemsInDirectory(parentPath, filter);
                
                InProgress = false;
                return true;
            }
            
            var isFile = File.Exists(realPath);
            var isDirectory = Directory.Exists(realPath);
            
            if (isDirectory)
            {
                System.GC.Collect();
                System.GC.WaitForPendingFinalizers();
                await RemoveDirectory(realPath);

                if (Directory.Exists(realPath))
                {
                    CmdAction permAction = new CmdAction()
                    {
                        Command = $"takeown /f \"{realPath}\" /r /d Y>NUL & icacls \"{realPath}\" /t /grant Administrators:F /c > NUL",
                        Timeout = 5000
                    };
                    try
                    {
                        await permAction.RunTask();
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "FileAction Error", realPath);
                    }

                    try
                    {
                        if (realPath.Contains("Defender"))
                        {
                            TaskKillAction killAction = new TaskKillAction()
                            {
                                ProcessName = "MsMpEng"
                            };

                            await killAction.RunTask();

                            killAction.ProcessName = "NisSrv";
                            await killAction.RunTask();

                            killAction.ProcessName = "SecurityHealthService";
                            await killAction.RunTask();

                            killAction.ProcessName = "smartscreen";
                            await killAction.RunTask();
                        }
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                            $"FileAction Error", realPath);
                    }
                    
                    await RemoveDirectory(realPath, true);

                    if (Directory.Exists(realPath))
                    {
                        //Delete the files in the initial directory. DOES delete directories.
                        await DeleteItemsInDirectory(realPath);

                        System.GC.Collect();
                        System.GC.WaitForPendingFinalizers();
                        await RemoveDirectory(realPath, true);
                    }
                }
            }
            else if (isFile)
            {
                try
                {
                    var lockedFilesList = new List<string> { "MpOAV.dll", "MsMpLics.dll", "EppManifest.dll", "MpAsDesc.dll", "MpClient.dll", "MsMpEng.exe" };
                    var fileName = realPath.Split('\\').LastOrDefault();

                    System.GC.Collect();
                    System.GC.WaitForPendingFinalizers();
                    await DeleteFile(realPath);

                    if (File.Exists(realPath))
                    {
                        CmdAction permAction = new CmdAction()
                        {
                            Command = $"takeown /f \"{realPath}\" /r /d Y>NUL & icacls \"{realPath}\" /t /grant Administrators:F /c > NUL",
                            Timeout = 5000
                        };
                        try
                        {
                            await permAction.RunTask();
                        }
                        catch (Exception e)
                        {
                            ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "FileAction Error", realPath);
                        }
                        
                        TaskKillAction taskKillAction = new TaskKillAction();

                        if (realPath.EndsWith(".sys"))
                        {
                            var driverService = Path.GetFileNameWithoutExtension(realPath);
                            try
                            {
                                //ServiceAction won't work here due to it not being able to detect driver services.
                                var cmdAction = new CmdAction();
                                Console.WriteLine($"Removing driver service {driverService}...");

                                cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                    $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop" :
                                    $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction stop";
                                await cmdAction.RunTask();

                                cmdAction.Command = Environment.Is64BitOperatingSystem ?
                                    $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete" :
                                    $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype service -cobject {driverService} -caction delete";
                                await cmdAction.RunTask();
                            }
                            catch (Exception servException)
                            {
                                ErrorLogger.WriteToErrorLog(servException.Message, servException.StackTrace,
                                    $"FileAction Error: Error trying to delete driver service {driverService}.", realPath);
                            }
                        }

                        if (lockedFilesList.Contains(fileName))
                        {
                            TaskKillAction killAction = new TaskKillAction()
                            {
                                ProcessName = "MsMpEng"
                            };

                            await killAction.RunTask();

                            killAction.ProcessName = "NisSrv";
                            await killAction.RunTask();

                            killAction.ProcessName = "SecurityHealthService";
                            await killAction.RunTask();

                            killAction.ProcessName = "smartscreen";
                            await killAction.RunTask();

                        }

                        var processes = new List<Process>();
                        try
                        {
                            processes = WinUtil.WhoIsLocking(realPath);
                        }
                        catch (Exception e)
                        {
                            ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                                $"FileAction Error", realPath);
                        }
                        var delay = 0;

                        int svcCount = 0;
                        foreach (var svchost in processes.Where(x => x.ProcessName.Equals("svchost")))
                        {
                            try
                            {
                                using var search = new ManagementObjectSearcher($"select * from Win32_Service where ProcessId = '{svchost.Id}'");

                                foreach (ManagementObject queryObj in search.Get())
                                {
                                    var serviceName = (string)queryObj["Name"]; // Access service name  
                                
                                    var serv = ServiceController.GetServices().FirstOrDefault(x => x.ServiceName.Equals(serviceName));

                                    if (serv == null) svcCount++;
                                    else svcCount += serv.DependentServices.Length + 1;
                                }
                            } catch (Exception e)
                            {
                                Console.WriteLine($"\r\nError: Could not get amount of services locking file.\r\nException: " + e.Message);
                            }
                        }
                        if (svcCount > 8) Console.WriteLine("Amount of locking services exceeds 8, skipping...");
                        
                        while (processes.Any() && delay <= 800 && svcCount <= 8)
                        {
                            Console.WriteLine("Processes locking the file:");
                            foreach (var process in processes)
                            {
                                Console.WriteLine(process.ProcessName);
                            }

                            foreach (var process in processes)
                            {
                                try
                                {
                                    if (process.ProcessName.Equals("TrustedUninstaller.CLI"))
                                    {
                                        Console.WriteLine("Skipping TU.CLI...");
                                        continue;
                                    }
                                    if (Regex.Match(process.ProcessName, "ame.?wizard", RegexOptions.IgnoreCase).Success)
                                    {
                                        Console.WriteLine("Skipping AME Wizard...");
                                        continue;
                                    }

                                    taskKillAction.ProcessName = process.ProcessName;
                                    taskKillAction.ProcessID = process.Id;

                                    Console.WriteLine($"Killing {process.ProcessName} with PID {process.Id}... it is locking {realPath}");
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
                                    await taskKillAction.RunTask();
                                }
                                catch (Exception e)
                                {
                                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                                        $"FileAction Error: Could not kill process {process.ProcessName}.");
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
                                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                                    $"FileAction Error", realPath);
                            }
                        
                            delay += 100;
                        }
                        if (delay >= 800)
                            ErrorLogger.WriteToErrorLog($"Could not kill locking processes for file '{realPath}'. Process termination loop exceeded max cycles (8).",
                                Environment.StackTrace, "FileAction Error");

                        await DeleteFile(realPath, true);
                    }
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                        $"FileAction Error: Error while trying to delete {realPath}.");
                }
                using (var writer = new StreamWriter("Logs\\FileChecklist.txt", true))
                {
                    writer.WriteLine($"File Path: {realPath}\r\nDeleted: {!File.Exists(realPath)}\r\n" +
                        $"======================");
                }
            }
            else
            {
                Console.WriteLine($"File or directory '{realPath}' not found.");
            }

            InProgress = false;
            return true;
        }
    }
}