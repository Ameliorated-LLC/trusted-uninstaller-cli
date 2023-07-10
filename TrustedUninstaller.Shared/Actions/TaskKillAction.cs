using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    class TaskKillAction : TaskAction, ITaskAction
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        
        [YamlMember(typeof(string), Alias = "name")]
        public string? ProcessName { get; set; }
        
        [YamlMember(typeof(string), Alias = "pathContains")]
        public string? PathContains { get; set; }
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 2;
        public int GetProgressWeight() => ProgressWeight;

        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public int? ProcessID { get; set; }
        
        public string ErrorString()
        {
            string text = $"TaskKillAction failed to kill processes matching '{ProcessName}'.";

            try
            {
                var processes = GetProcess().Select(process => process.ProcessName).Distinct().ToList();
                if (processes.Count > 1)
                {
                    text = $"TaskKillAction failed to kill processes:";
                    foreach (var process in processes)
                    {
                        text += "|NEWLINE|" + process;
                    }
                }
                else if (processes.Count == 1) text = $"TaskKillAction failed to kill process {processes[0]}.";
            } catch (Exception) { }

            return text;
        }

        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            List<Process> processToTerminate = new List<Process>();
            if (ProcessID.HasValue)
            {
                try { processToTerminate.Add(Process.GetProcessById((int)ProcessID)); } catch (Exception) { } 
            }
            else
            {
                processToTerminate = GetProcess().ToList();
            }

            return processToTerminate.Any() ? UninstallTaskStatus.ToDo : UninstallTaskStatus.Completed;
        }

        private IEnumerable<Process> GetProcess()
        {
            if (ProcessName == null) return new List<Process>();
            
            if (ProcessName.EndsWith("*") && ProcessName.StartsWith("*")) return Process.GetProcesses()
                .Where(process => process.ProcessName.IndexOf(ProcessName.Trim('*'), StringComparison.CurrentCultureIgnoreCase) >= 0);
            if (ProcessName.EndsWith("*")) return Process.GetProcesses()
                .Where(process => process.ProcessName.StartsWith(ProcessName.TrimEnd('*'), StringComparison.CurrentCultureIgnoreCase));
            if (ProcessName.StartsWith("*")) return Process.GetProcesses()
                .Where(process => process.ProcessName.EndsWith(ProcessName.TrimStart('*'), StringComparison.CurrentCultureIgnoreCase));

            return Process.GetProcessesByName(ProcessName);
        } 
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool IsProcessCritical(IntPtr hProcess, ref bool Critical);
        
        private readonly string[] RegexNoKill = { "lsass", "csrss", "winlogon", "TrustedUninstaller\\.CLI", "dwm", "conhost", "ame.?wizard", "ame.?assassin" };
        // These processes give access denied errors when getting their handle for IsProcessCritical.
        // TODO: Investigate how to properly acquire permissions.
        private readonly string[] RegexNotCritical = { "SecurityHealthService", "wscsvc", "MsMpEng", "SgrmBroker" };
        public async Task<bool> RunTask()
        {
            InProgress = true;
            
            if (string.IsNullOrEmpty(ProcessName) && ProcessID.HasValue)
            {
                Console.WriteLine($"Killing process with PID '{ProcessID.Value}'...");
            }
            else
            {
                if (ProcessName != null && RegexNoKill.Any(regex => Regex.Match(ProcessName, regex, RegexOptions.IgnoreCase).Success))
                {
                    Console.WriteLine($"Skipping {ProcessName}...");
                    return false;
                }
                
                Console.WriteLine($"Killing processes matching '{ProcessName}'...");
            }
            var cmdAction = new CmdAction();
            
            if (ProcessName != null)
            {
                //If the service is svchost, we stop the service instead of killing it.
                if (ProcessName.Contains("svchost"))
                {
                    // bool serviceFound = false;
                    try
                    {
                        using var search = new ManagementObjectSearcher($"select * from Win32_Service where ProcessId = '{ProcessID}'");

                        foreach (ManagementObject queryObj in search.Get())
                        {
                            var serviceName = (string)queryObj["Name"]; // Access service name  
                            
                            var stopServ = new ServiceAction()
                            {
                                ServiceName = serviceName,
                                Operation = ServiceOperation.Stop

                            };
                            await stopServ.RunTask();
                        }
                    }
                    catch (NullReferenceException e)
                    {
                        Console.WriteLine($"A service with PID: {ProcessID} could not be found.");
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, $"Could not find service with PID {ProcessID}.");
                    }


/*                    foreach (var serv in servicesToDelete)
                    {
                        //The ID can only be associated with one of the services, there's no need to loop through
                        //them all if we already found the service.
                        if (serviceFound)
                        {
                            break;
                        }

                        try
                        {
                            using var search = new ManagementObjectSearcher($"select ProcessId from Win32_Service where Name = '{serv}'").Get();
                            var servID = (uint)search.OfType<ManagementObject>().FirstOrDefault()["ProcessID"];

                            if (servID == ProcessID)
                            {
                                serviceFound = true;



                            }
                            search.Dispose();
                        }
                        catch (Exception e)
                        {
                            var search = new ManagementObjectSearcher($"select Name from Win32_Service where ProcessID = '{ProcessID}'").Get();
                            var servName = search.OfType<ManagementObject>().FirstOrDefault()["Name"];
                            Console.WriteLine($"Could not find {servName} but PID {ProcessID} still exists.");
                            ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, $"Exception Type: {e.GetType()}");
                            return false;
                        }
                    }*/
                    //None of the services listed, we shouldn't kill svchost.
/*                    if (!serviceFound)
                    {
                        var search = new ManagementObjectSearcher($"select Name from Win32_Service where ProcessID = '{ProcessID}'").Get();
                        var servName = search.OfType<ManagementObject>().FirstOrDefault()["Name"];
                        Console.WriteLine($"A critical system process \"{servName}\" with PID {ProcessID} caused the Wizard to fail.");
                        await WinUtil.UninstallDriver();
                        Environment.Exit(-1);
                        return false;
                    }*/

                    await Task.Delay(100);

                    InProgress = false;
                    return true;
                }

                if (PathContains != null && !ProcessID.HasValue)
                {
                    var processes = GetProcess().ToList();
                    if (processes.Count > 0) Console.WriteLine("Processes:");

                    foreach (var process in processes.Where(x => x.MainModule.FileName.Contains(PathContains)))
                    {
                        Console.WriteLine(process.ProcessName + " - " + process.Id);

                        if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success)) {
                            bool isCritical = false;
                            IsProcessCritical(process.Handle, ref isCritical);
                            if (isCritical)
                            {
                                Console.WriteLine($"{process.ProcessName} is a critical process, skipping...");
                                continue;
                            }
                        }
                        
                        cmdAction.Command = Environment.Is64BitOperatingSystem ?
                            $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate" :
                            $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate";
                        await cmdAction.RunTask();
                        
                        int i = 0;
                        while (i <= 15 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                        {
                            await Task.Delay(300);
                            i++;
                        }
                        if (i >= 15) ErrorLogger.WriteToErrorLog($"Task kill timeout exceeded.", Environment.StackTrace, "TaskKillAction Error");
                    }
                    InProgress = false;
                    return true;
                }
            }
            
            if (ProcessID.HasValue)
            {
                if (ProcessName != null && ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var process = Process.GetProcessById(ProcessID.Value);
                        TerminateProcess(process.Handle, 1);
                    } catch (Exception)
                    {
                        cmdAction.Command = Environment.Is64BitOperatingSystem ?
                            $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID} -caction terminate" :
                            $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID} -caction terminate";
                        await cmdAction.RunTask();
                    }
                }
                else
                {
                    var process = Process.GetProcessById(ProcessID.Value);

                    if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                    {
                        bool isCritical = false;
                        try
                        {
                            IsProcessCritical(process.Handle, ref isCritical);
                        }
                        catch (InvalidOperationException e)
                        {
                            ErrorLogger.WriteToErrorLog("Could not check if process is critical.", e.StackTrace, "TaskKillAction Error", process.ProcessName);
                            return false;
                        }
                        if (isCritical)
                        {
                            Console.WriteLine($"{process.ProcessName} is a critical process, skipping...");
                            return false;
                        }
                    }
                    cmdAction.Command = Environment.Is64BitOperatingSystem ?
                        $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID} -caction terminate" :
                        $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID} -caction terminate";
                    await cmdAction.RunTask();
                }

                await Task.Delay(100);
            }
            else
            {
                var processes = GetProcess().ToList();
                if (processes.Count > 0) Console.WriteLine("Processes:");

                foreach (var process in processes)
                {
                    Console.WriteLine(process.ProcessName + " - " + process.Id);
                    
                    cmdAction.Command = Environment.Is64BitOperatingSystem ?
                        $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.ProcessName}.exe -caction terminate" :
                        $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.ProcessName}.exe -caction terminate";
                    if (process.ProcessName == "explorer") TerminateProcess(process.Handle, 1);
                    else
                    {
                        if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                        {
                            bool isCritical = false;
                            try
                            {
                                IsProcessCritical(process.Handle, ref isCritical);
                            }
                            catch (InvalidOperationException e)
                            {
                                ErrorLogger.WriteToErrorLog("Could not check if process is critical.", e.StackTrace, "TaskKillAction Error", process.ProcessName);
                                continue;
                            }
                            if (isCritical)
                            {
                                Console.WriteLine($"{process.ProcessName} is a critical process, skipping...");
                                continue;
                            }
                        }

                        await cmdAction.RunTask();
                    }

                    int i = 0;

                    while (i <= 15 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                    {
                        await Task.Delay(300);
                        i++;
                    }
                    if (i >= 15) ErrorLogger.WriteToErrorLog($"Task kill timeout exceeded.", Environment.StackTrace, "TaskKillAction Error");
                }
            }
            
            InProgress = false;
            return true;
        }
    }
}
