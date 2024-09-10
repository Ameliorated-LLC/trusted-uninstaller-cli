using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Core;
using JetBrains.Annotations;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class PowerShellAction : Tasks.TaskActionWithOutputProcessor, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output)
        {
            if (InProgress) throw new TaskInProgressException("Another Powershell action was called while one was in progress.");
            InProgress = true;
            
            var privilegeText = RunAs == Privilege.CurrentUser ? " as the current user" : RunAs == Privilege.CurrentUserElevated ? " as the current user elevated" : RunAs == Privilege.System ?
                " as the system account" : "";
            
            output.WriteLineSafe("Info", $"Running PowerShell command '{Command}'{privilegeText}...");

            WinUtil.CheckKph();

            if (RunAs == Privilege.TrustedInstaller)
                RunAsProcess(output);
            else
                RunAsPrivilegedProcess(output);

            InProgress = false;
            return;
        }
        [YamlMember(typeof(Privilege), Alias = "runas")]
        public Privilege RunAs { get; set; } = Privilege.TrustedInstaller;
        
        [YamlMember(typeof(string), Alias = "command")]
        public string Command { get; set; }
        
        [YamlMember(typeof(string), Alias = "timeout")]
        public int? Timeout { get; set; }
        
        [YamlMember(typeof(string), Alias = "wait")]
        public bool Wait { get; set; } = true;
        
        [YamlMember(typeof(bool), Alias = "exeDir")]
        public bool ExeDir { get; set; } = false;
        
        [YamlMember(typeof(Dictionary<string, ExitCodeAction>), Alias = "handleExitCodes")]
        [CanBeNull] public Dictionary<string, ExitCodeAction> HandleExitCodes { get; set; } = null;

        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        
        private int? ExitCode { get; set; }
        
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => false;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"PowerShellAction failed to run command '{Command}'.";
        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return ExitCode == null ? UninstallTaskStatus.ToDo: UninstallTaskStatus.Completed;
        }

        public Task<bool> RunTask(Output.OutputWriter output)
        {
            return null;
        }
        
        private void RunAsProcess(Output.OutputWriter output)
        {            
            using var process = new Process();
            var startInfo = new ProcessStartInfo
            {
                WindowStyle = ProcessWindowStyle.Normal,
                FileName = "PowerShell.exe",
                Arguments = $@"-NoP -ExecutionPolicy Bypass -NonInteractive -C ""{Command}""",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            if (ExeDir) startInfo.WorkingDirectory = AmeliorationUtil.Playbook.Path + "\\Executables";
            if (!Wait)
            {
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.UseShellExecute = true;
            }
                
            process.StartInfo = startInfo;
            using (var handler = new OutputHandler("Process", process, output))
            {
                handler.StartProcess(RunAs);
             
                if (!Wait)
                {
                    return;
                }
                
                if (Timeout.HasValue)
                {
                    var exited = process.WaitForExit(Timeout.Value);
                    if (!exited)
                    {
                        handler.CancelReading();
                        process.Kill();
                        throw new TimeoutException($"Executable run timeout exceeded.");
                    }
                }
                else
                {
                    bool exited = process.WaitForExit(30000);

                    // WaitForExit alone seems to not be entirely reliable
                    while (!exited && PowerShellRunning(process.Id))
                    {
                        exited = process.WaitForExit(30000);
                    }
                }
            }

            ExitCode = Wrap.ExecuteSafe(() => process.ExitCode, true, output.LogOptions).Value;
            if (ExitCode != 0)
                output.WriteLineSafe("Info", $"PowerShell instance exited with error code: {ExitCode}");
            
            if (HandleExitCodes != null)
            {
                foreach (string key in HandleExitCodes.Keys)
                {
                    if (IsApplicableNumber(key, ExitCode.Value))
                    {
                        throw new ErrorHandlingException(HandleExitCodes[key], $"PowerShell command '{Command}' exit code {ExitCode.Value} handled with filter '{key}' --> {HandleExitCodes[key]}.");
                    }
                }
            }
        }
        
        private static bool PowerShellRunning(int id)
        {
            try
            {
                return Process.GetProcessesByName("powershell").Any(x => x.Id == id);
            }
            catch (Exception)
            {
                return false;
            }
        }
        
        private void RunAsPrivilegedProcess(Output.OutputWriter output)
        {
            using var process = new AugmentedProcess.Process();
            var startInfo = new AugmentedProcess.ProcessStartInfo
            {
                WindowStyle = ProcessWindowStyle.Normal,
                FileName = "PowerShell.exe",
                Arguments = $@"-NoP -ExecutionPolicy Bypass -NonInteractive -C ""{Command}""",
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            if (ExeDir) startInfo.WorkingDirectory = AmeliorationUtil.Playbook.Path + "\\Executables";
            if (!Wait)
            {
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.UseShellExecute = true;
            }
            
            process.StartInfo = startInfo;
            
            using (var handler = new OutputHandler("Process", process, output))
            {
                handler.StartProcess(RunAs);
             
                if (!Wait)
                {
                    return;
                }
                
                if (Timeout.HasValue)
                {
                    var exited = process.WaitForExit(Timeout.Value);
                    if (!exited)
                    {
                        handler.CancelReading();
                        process.Kill();
                        throw new TimeoutException($"Executable run timeout exceeded.");
                    }
                }
                else process.WaitForExit();
            }

            ExitCode = Wrap.ExecuteSafe(() => process.ExitCode, true, output.LogOptions).Value;
            if (ExitCode != 0)
                output.WriteLineSafe("Info", $"PowerShell instance exited with error code: {ExitCode}");
            
            if (HandleExitCodes != null)
            {
                foreach (string key in HandleExitCodes.Keys)
                {
                    if (IsApplicableNumber(key, ExitCode.Value))
                    {
                        throw new ErrorHandlingException(HandleExitCodes[key], $"PowerShell command '{Command}' exit code {ExitCode.Value} handled with filter '{key}' --> {HandleExitCodes[key]}.");
                    }
                }
            }
        }
    }
}
