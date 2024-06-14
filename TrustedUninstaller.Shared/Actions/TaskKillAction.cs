using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using Core;

namespace TrustedUninstaller.Shared.Actions
{
    class TaskKillAction : Tasks.TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle, int dwProcessId);
        
        public enum ProcessAccessFlags : uint
        {
            QueryLimitedInformation = 0x1000
        }
        
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);
        
        [YamlMember(typeof(string), Alias = "name")]
        public string? ProcessName { get; set; }
        
        [YamlMember(typeof(string), Alias = "pathContains")]
        public string? PathContains { get; set; }
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 2;
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Log;
        public bool GetRetryAllowed() => true;

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

        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
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

        private List<Process> GetProcess()
        {
            if (ProcessID.HasValue)
            {
                var list = new List<Process>();
                try
                {
                    var process = Process.GetProcessById(ProcessID.Value);
                    if (ProcessName == null || process.ProcessName.Equals(ProcessName, StringComparison.OrdinalIgnoreCase))
                        list.Add(process);
                    else
                        return list;
                }
                catch (Exception e)
                {
                    return list;
                } 
            }
            
            if (ProcessName == null)
            {
                return new List<Process>();
            }
            
            if (ProcessName.EndsWith("*") && ProcessName.StartsWith("*")) return Process.GetProcesses().ToList()
                .Where(process => process.ProcessName.IndexOf(ProcessName.Trim('*'), StringComparison.CurrentCultureIgnoreCase) >= 0).ToList();
            if (ProcessName.EndsWith("*")) return Process.GetProcesses()
                .Where(process => process.ProcessName.StartsWith(ProcessName.TrimEnd('*'), StringComparison.CurrentCultureIgnoreCase)).ToList();
            if (ProcessName.StartsWith("*")) return Process.GetProcesses()
                .Where(process => process.ProcessName.EndsWith(ProcessName.TrimStart('*'), StringComparison.CurrentCultureIgnoreCase)).ToList();

            return Process.GetProcessesByName(ProcessName).ToList();
        } 
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool IsProcessCritical(IntPtr hProcess, ref bool Critical);
        
        private readonly string[] RegexNoKill = { "lsass", "csrss", "winlogon", "TrustedUninstaller\\.CLI", "dwm", "conhost", "ame.?wizard", "ame.?assassin" };
        // These processes give access denied errors when getting their handle for IsProcessCritical.
        // TODO: Investigate how to properly acquire permissions.
        private readonly string[] RegexNotCritical = { "SecurityHealthService", "wscsvc", "MsMpEng", "SgrmBroker" };
        public async Task<bool> RunTask(Output.OutputWriter output)
        {
            InProgress = true;
            
            if (string.IsNullOrEmpty(ProcessName) && ProcessID.HasValue)
            {
                output.WriteLineSafe("Info", $"Killing process with PID '{ProcessID.Value}'...");
            }
            else
            {
                if (ProcessName != null && RegexNoKill.Any(regex => Regex.Match(ProcessName, regex, RegexOptions.IgnoreCase).Success))
                {
                    output.WriteLineSafe("Info", $"Skipping {ProcessName}...");
                    return false;
                }
                
                output.WriteLineSafe("Info", $"Killing processes matching '{ProcessName}'...");
            }
            var cmdAction = new CmdAction();
            
            if (ProcessName != null)
            {
                //If the service is svchost, we stop the service instead of killing it.
                if (ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        if (ProcessID.HasValue)
                        {
                            foreach (var serviceName in Win32.ServiceEx.GetServicesFromProcessId(ProcessID.Value))
                            {
                                try
                                {
                                    var stopServ = new ServiceAction()
                                    {
                                        ServiceName = serviceName,
                                        Operation = ServiceOperation.Stop
                                    };
                                    await stopServ.RunTask(output);
                                }
                                catch (Exception e)
                                {
                                    output.WriteLineSafe("Info", $"Could not kill service " + serviceName + ": " + e.Message);
                                    Log.WriteExceptionSafe(LogType.Warning, e, $"Could not kill service.", output.LogOptions);
                                }
                            }
                        }
                        else
                        {
                            foreach (var process in GetProcess())
                            {
                                foreach (var serviceName in Win32.ServiceEx.GetServicesFromProcessId(process.Id))
                                {
                                    try
                                    {
                                        var stopServ = new ServiceAction()
                                        {
                                            ServiceName = serviceName,
                                            Operation = ServiceOperation.Stop

                                        };
                                        await stopServ.RunTask(output);
                                    }
                                    catch (Exception e)
                                    {
                                        output.WriteLineSafe("Info", $"Could not kill service " + serviceName + ": " + e.Message);
                                        Log.WriteExceptionSafe(LogType.Warning, e, $"Could not kill service", output.LogOptions);
                                    }
                                }
                            }
                        }
                    }
                    catch (NullReferenceException e)
                    {
                        output.WriteLineSafe("Info", $"A service with PID: {ProcessID.Value} could not be found.");
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Could not find service with PID {ProcessID.Value}.", output.LogOptions);
                    }

                    int i;
                    for (i = 0; i <= 6 && GetProcess().Any(); i++)
                    {
                        await Task.Delay(100 * i);
                    }
                    if (i < 6)
                    {
                        InProgress = false;
                        return true;
                    }
                }

                if (PathContains != null && !ProcessID.HasValue)
                {
                    var processes = GetProcess();
                    if (processes.Count > 0) output.WriteLineSafe("Info", "Processes:");

                    foreach (var process in processes.Where(x =>
                             {
                                 try
                                 {
                                     return x.MainModule.FileName.Contains(PathContains);
                                 }
                                 catch (Exception e)
                                 {
                                     return false;
                                 }
                             }))
                    {
                        output.WriteLineSafe("Info", process.ProcessName + " - " + process.Id);

                        if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                        {
                            bool isCritical = false;
                            IntPtr hprocess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, process.Id);
                            IsProcessCritical(hprocess, ref isCritical);
                            CloseHandle(hprocess);
                            if (isCritical)
                            {
                                output.WriteLineSafe("Info", $"{process.ProcessName} is a critical process, skipping...");
                                continue;
                            }
                        }
                        try
                        {
                            if (!process.HasExited && !TerminateProcess(process.Handle, 1))
                                Log.WriteExceptionSafe(LogType.Warning, new Win32Exception(), $"TerminateProcess failed with error code.", output.LogOptions);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, $"Could not open process handle.", output.LogOptions);
                        }
                        try
                        {
                            process.WaitForExit(1000);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, $"Error waiting for process exit.", output.LogOptions);
                        }

                        if (process.ProcessName == "explorer") continue;

                        cmdAction.Command = Environment.Is64BitOperatingSystem ?
                            $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate" :
                            $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate";
                        if (AmeliorationUtil.UseKernelDriver && process.ProcessName != "explorer") cmdAction.RunTaskOnMainThread(output);

                        int i = 0;

                        while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                        {
                            try
                            {
                                try
                                {
                                    if (AmeliorationUtil.UseKernelDriver)
                                        cmdAction.RunTaskOnMainThread(output);
                                    else
                                        TerminateProcess(process.Handle, 1);
                                }
                                catch (Exception e) { }

                                process.WaitForExit(500);
                            }
                            catch (Exception e) { }
                            await Task.Delay(100);
                            i++;
                        }
                        if (i >= 3) Log.WriteSafe(LogType.Warning, $"Task kill timeout exceeded.", new SerializableTrace(), output.LogOptions);

                    }
                    InProgress = false;
                    return true;
                }
            }
            if (ProcessID.HasValue)
            {
                var process = Process.GetProcessById(ProcessID.Value);
                if (ProcessName != null && ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                {
                    try {
                        if (!process.HasExited && !TerminateProcess(process.Handle, 1))
                            Log.WriteExceptionSafe(LogType.Warning, new Win32Exception(), $"TerminateProcess failed with error code.", output.LogOptions);

                        try
                        {
                            process.WaitForExit(1000);
                        }
                        catch (Exception e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, $"Error waiting for process exit.", output.LogOptions);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Could not open process handle.", output.LogOptions);
                    }
                }
                else
                {
                    if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                    {
                        bool isCritical = false;
                        try
                        {
                            IntPtr hprocess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, process.Id);
                            IsProcessCritical(hprocess, ref isCritical);
                            CloseHandle(hprocess);
                        }
                        catch (InvalidOperationException e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, $"Could not check if process is critical.", output.LogOptions);
                            return false;
                        }
                        if (isCritical)
                        {
                            output.WriteLineSafe("Info", $"{process.ProcessName} is a critical process, skipping...");
                            return false;
                        }
                    }
                    try
                    {
                        if (!process.HasExited && !TerminateProcess(process.Handle, 1))
                            Log.WriteExceptionSafe(LogType.Warning, new Win32Exception(), $"TerminateProcess failed with error code.", output.LogOptions);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Could not open process handle.", output.LogOptions);
                    }
                    try
                    {
                        process.WaitForExit(1000);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Error waiting for process exit.", output.LogOptions);
                    }
                    
                    cmdAction.Command = Environment.Is64BitOperatingSystem ?
                        $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID.Value} -caction terminate" :
                        $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {ProcessID.Value} -caction terminate";
                    if (AmeliorationUtil.UseKernelDriver) cmdAction.RunTaskOnMainThread(output);
                }
                
                int i = 0;
                
                while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                {
                    try
                    {
                        try
                        {
                            if (AmeliorationUtil.UseKernelDriver)
                                cmdAction.RunTaskOnMainThread(output);
                            else
                                TerminateProcess(process.Handle, 1);
                        }
                        catch (Exception e)
                        {
                        }

                        process.WaitForExit(500);
                    }
                    catch (Exception e)
                    {
                    }
                    await Task.Delay(100);
                    i++;
                }
                if (i >= 3) Log.WriteSafe(LogType.Warning, $"Task kill timeout exceeded.", new SerializableTrace(), output.LogOptions);
            }
            else
            {
                var processes = GetProcess();
                if (processes.Count > 0) output.WriteLineSafe("Info", "Processes:");

                foreach (var process in processes)
                {
                    output.WriteLineSafe("Info", process.ProcessName + " - " + process.Id);

                    if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                    {
                        bool isCritical = false;
                        try
                        {
                            IntPtr hprocess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, process.Id);
                            IsProcessCritical(hprocess, ref isCritical);
                            CloseHandle(hprocess);
                        }
                        catch (InvalidOperationException e)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, e, $"Could not check if process is critical.", output.LogOptions);
                            continue;
                        }
                        if (isCritical)
                        {
                            output.WriteLineSafe("Info", $"{process.ProcessName} is a critical process, skipping...");
                            continue;
                        }
                    }
                    try
                    {
                        if (!process.HasExited && !TerminateProcess(process.Handle, 1))
                            Log.WriteExceptionSafe(LogType.Warning, new Win32Exception(), $"TerminateProcess failed with error code.", output.LogOptions);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Could not open process handle.", output.LogOptions);
                    }
                    try
                    {
                        process.WaitForExit(1000);
                    }
                    catch (Exception e)
                    {
                        Log.WriteExceptionSafe(LogType.Warning, e, $"Error waiting for process exit.", output.LogOptions);
                    }
                    
                    if (process.ProcessName == "explorer") continue;
                    
                    cmdAction.Command = Environment.Is64BitOperatingSystem ?
                        $"ProcessHacker\\x64\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate" :
                        $"ProcessHacker\\x86\\ProcessHacker.exe -s -elevate -c -ctype process -cobject {process.Id} -caction terminate";
                    if (AmeliorationUtil.UseKernelDriver && process.ProcessName != "explorer") cmdAction.RunTaskOnMainThread(output);

                    int i = 0;

                    while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                    {
                        try
                        {
                            try
                            {
                                if (AmeliorationUtil.UseKernelDriver)
                                    cmdAction.RunTaskOnMainThread(output);
                                else
                                    TerminateProcess(process.Handle, 1);
                            }
                            catch (Exception e)
                            {
                            }

                            process.WaitForExit(500);
                        }
                        catch (Exception e)
                        {
                        }
                        await Task.Delay(100);
                        i++;
                    }
                    if (i >= 3) Log.WriteSafe(LogType.Warning, $"Task kill timeout exceeded.", new SerializableTrace(), output.LogOptions);
                }
            }
            
            InProgress = false;
            return true;
        }
    }
}
