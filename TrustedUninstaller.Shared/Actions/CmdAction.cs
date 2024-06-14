using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Core;
using JetBrains.Annotations;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class CmdAction : Tasks.TaskActionWithOutputProcessor, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output)
        {
            if (InProgress) throw new TaskInProgressException("Another Cmd action was called while one was in progress.");
            InProgress = true;
            
            var privilegeText = RunAs == Privilege.CurrentUser ? " as the current user" : RunAs == Privilege.CurrentUserElevated ? " as the current user elevated" : RunAs == Privilege.System ?
                " as the system account" : "";
            
            output.WriteLineSafe("Info", $"Running cmd command '{Command}'{privilegeText}...");

            ExitCode = null;

            if (RunAs == Privilege.TrustedInstaller)
                RunAsProcess(output);
            else
                RunAsPrivilegedProcess(output);

            InProgress = false;
        }
        [YamlMember(typeof(Privilege), Alias = "runas")]
        public Privilege RunAs { get; set; } = Privilege.TrustedInstaller;
        
        [YamlMember(typeof(string), Alias = "command")]
        public string Command { get; set; }
        
        [YamlMember(typeof(int), Alias = "timeout")]
        public int? Timeout { get; set; }
        
        [YamlMember(typeof(string), Alias = "wait")]
        public bool Wait { get; set; } = true;
        
        [YamlMember(typeof(bool), Alias = "exeDir")]
        public bool ExeDir { get; set; } = false;
        
        [YamlMember(typeof(Dictionary<string, ExitCodeAction>), Alias = "handleExitCodes")]
        [CanBeNull] public Dictionary<string, ExitCodeAction> HandleExitCodes { get; set; } = null;

        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => false;

        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        private int? ExitCode { get; set; }


        public string ErrorString() => $"CmdAction failed to run command '{Command}'.";
        
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
                FileName = "cmd.exe",
                Arguments = "/C " + $"\"{this.Command}\"",
                UseShellExecute = false,
                // .NET has a bug when the start command is used. Using WaitForExit() waits for the
                // started process to exit, instead of just the original cmd.exe process. For some
                // reason, using WaitForExit(timeout) does not have this same behavior, and returns
                // after start finishes as expected. However, the output streams do not output null
                // either until the started process exits, which is why an exception is made here.
                // Same for .NET 8.0.
                RedirectStandardError = !this.Command.StartsWith("start ", StringComparison.OrdinalIgnoreCase),
                RedirectStandardOutput = !this.Command.StartsWith("start ", StringComparison.OrdinalIgnoreCase),
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
                        throw new TimeoutException($"Command '{Command}' timeout exceeded.");
                    }
                }
                else
                {
                    bool exited = process.WaitForExit(30000);

                    // WaitForExit alone seems to not be entirely reliable
                    while (!exited && CmdRunning(process.Id))
                    {
                        exited = process.WaitForExit(30000);
                    }
                }
            }
            
            ExitCode = Wrap.ExecuteSafe(() => process.ExitCode, true, output.LogOptions).Value;
            if (ExitCode != 0 && !Command.Contains("ProcessHacker\\x64\\ProcessHacker.exe"))
                output.WriteLineSafe("Info", $"cmd instance exited with non-zero exit code: {ExitCode}");
            
            if (HandleExitCodes != null)
            {
                foreach (string key in HandleExitCodes.Keys)
                {
                    if (IsApplicableNumber(key, ExitCode.Value))
                    {
                        throw new ErrorHandlingException(HandleExitCodes[key], $"Command '{Command}' exit code {ExitCode.Value} handled with filter '{key}' --> {HandleExitCodes[key]}.");
                    }
                }
            }
        }
        
        private static bool CmdRunning(int id)
        {
            try
            {
                return Process.GetProcessesByName("cmd").Any(x => x.Id == id);
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
                FileName = "cmd.exe",
                Arguments = "/C " + $"{this.Command}",
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
                        throw new TimeoutException($"Command '{Command}' timeout exceeded.");
                    }
                }
                else process.WaitForExit();
            }
            
            ExitCode = Wrap.ExecuteSafe(() => process.ExitCode, true, output.LogOptions).Value;
            if (ExitCode != 0 && !Command.Contains("ProcessHacker\\x64\\ProcessHacker.exe"))
                output.WriteLineSafe("Info", $"cmd instance exited with non-zero exit code: {ExitCode}");
        }
    }
}
