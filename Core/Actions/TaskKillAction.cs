using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using YamlDotNet.Serialization;
using Core;

namespace Core.Actions
{
    class TaskKillAction : ICoreAction
    {
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
        public void RunTask(bool logExceptions = true)
        {
            InProgress = true;
            
            if (string.IsNullOrEmpty(ProcessName) && ProcessID.HasValue)
            {

            }
            else
            {
                if (ProcessName != null && RegexNoKill.Any(regex => Regex.Match(ProcessName, regex, RegexOptions.IgnoreCase).Success))
                {
                    return;
                }
            }
            
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
                                    stopServ.RunTask();
                                }
                                catch (Exception e)
                                {
                                    if (logExceptions)
                                        Log.EnqueueExceptionSafe(e, "Could not kill service " + serviceName);
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
                                        stopServ.RunTask();
                                    }
                                    catch (Exception e)
                                    {
                                        if (logExceptions)
                                            Log.EnqueueExceptionSafe(e, "Could not kill service " + serviceName);
                                    }
                                }
                            }
                        }
                    }
                    catch (NullReferenceException e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(e, $"Could not find service with PID {ProcessID.Value}.");
                    }

                    int i;
                    for (i = 0; i <= 6 && GetProcess().Any(); i++)
                    {
                        Thread.Sleep(100 * i);
                    }
                    if (i < 6)
                    {
                        InProgress = false;
                        return;
                    }
                }

                if (PathContains != null && !ProcessID.HasValue)
                {
                    var processes = GetProcess();

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

                        if (!RegexNotCritical.Any(x => Regex.Match(process.ProcessName, x, RegexOptions.IgnoreCase).Success))
                        {
                            bool isCritical = false;
                            IntPtr hprocess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, process.Id);
                            IsProcessCritical(hprocess, ref isCritical);
                            CloseHandle(hprocess);
                            if (isCritical)
                            {
                                continue;
                            }
                        }
                        try
                        {
                            if (!TerminateProcess(process.Handle, 1) && logExceptions)
                                Log.EnqueueExceptionSafe(new Win32Exception(), $"Could not find service with PID {ProcessID.Value}.");
                        }
                        catch (Exception e)
                        {
                            if (logExceptions)
                                Log.EnqueueExceptionSafe(e);
                        }
                        try
                        {
                            process.WaitForExit(1000);
                        }
                        catch (Exception e)
                        {
                            if (logExceptions)
                                Log.EnqueueExceptionSafe(e);
                        }

                        if (process.ProcessName == "explorer") continue;

                        int i = 0;

                        while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                        {
                            Wrap.ExecuteSafe(() => TerminateProcess(process.Handle, 1));
                            process.WaitForExit(500);
 
                            Thread.Sleep(100);
                            i++;
                        }
                        if (i >= 3 && logExceptions) Log.EnqueueSafe(LogType.Error, "Task kill timeout exceeded.", new SerializableTrace());

                    }
                    InProgress = false;
                    return;
                }
            }
            if (ProcessID.HasValue)
            {
                var process = Process.GetProcessById(ProcessID.Value);
                if (ProcessName != null && ProcessName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                {
                    try {
                        if (!TerminateProcess(process.Handle, 1) && logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, new Win32Exception(), "TerminateProcess failed with error code.", ("Process", ProcessName));

                        try
                        {
                            process.WaitForExit(1000);
                        }
                        catch (Exception e)
                        {
                            if (logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Error waiting for process exit.", ("Process", ProcessName));
                        }
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not open process handle.", ("Process", ProcessName));
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
                            if (logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not check if process is critical.", ("Process", ProcessName));
                            return;
                        }
                        if (isCritical)
                        {
                            Console.WriteLine($"{process.ProcessName} is a critical process, skipping...");
                            return;
                        }
                    }
                    try
                    {
                        if (!TerminateProcess(process.Handle, 1) && logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, new Win32Exception(), "TerminateProcess failed with error code.", ("Process", ProcessName));
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not open process handle.", ("Process", ProcessName));
                    }
                    try
                    {
                        process.WaitForExit(1000);
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Error waiting for process exit.", ("Process", ProcessName));
                    }
                }
                
                int i = 0;
                
                while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                {
                    try
                    {
                        try
                        {
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
                    Thread.Sleep(100);
                    i++;
                }
                if (i >= 3 && logExceptions) Log.EnqueueSafe(LogType.Warning, "Task kill timeout exceeded.", new SerializableTrace(), ("Process", ProcessName));
            }
            else
            {
                var processes = GetProcess();

                foreach (var process in processes)
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
                            if (logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not check if process is critical.", ("Process", ProcessName));
                            continue;
                        }
                        if (isCritical)
                        {
                            continue;
                        }
                    }
                    try
                    {
                        if (!TerminateProcess(process.Handle, 1) && logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, new Win32Exception(), "TerminateProcess failed with error code.", ("Process", ProcessName));
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not open process handle.", ("Process", ProcessName));
                    }
                    try
                    {
                        process.WaitForExit(1000);
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Error waiting for process exit.", ("Process", ProcessName));
                    }
                    
                    if (process.ProcessName == "explorer") continue;

                    int i = 0;

                    while (i <= 3 && GetProcess().Any(x => x.Id == process.Id && x.ProcessName == process.ProcessName))
                    {
                        try
                        {
                            try
                            {
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
                        Thread.Sleep(100);
                        i++;
                    }
                    if (i >= 3 && logExceptions) Log.EnqueueSafe(LogType.Warning, "Task kill timeout exceeded.", new SerializableTrace(), ("Process", ProcessName));
                }
            }
            
            InProgress = false;
            return;
        }
    }
}
