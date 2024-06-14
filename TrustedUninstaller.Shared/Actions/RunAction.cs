using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Documents;
using Core;
using JetBrains.Annotations;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class RunAction : Tasks.TaskActionWithOutputProcessor, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output)
        {
            if (RawPath != null) RawPath = Environment.ExpandEnvironmentVariables(RawPath);
            InProgress = true;

            var privilegeText = RunAs == Privilege.CurrentUser ? " as the current user" : RunAs == Privilege.CurrentUserElevated ? " as the current user elevated" : RunAs == Privilege.System ?
                " as the system account" : RunAs == Privilege.CurrentUserTrustedInstaller ? " as the current user trusted installer" : "";
            
            if (Arguments == null) output.WriteLineSafe("Info", $"Running '{Exe + privilegeText}'...");
            else output.WriteLineSafe("Info", $"Running '{Exe}' with arguments '{Arguments + "'" + privilegeText}...");

            WinUtil.CheckKph();
            
            var currentDir = Directory.GetCurrentDirectory();
            
            if (ExeDir) RawPath = AmeliorationUtil.Playbook.Path + "\\Executables";
            if (BaseDir) RawPath = currentDir;

            string file = null;
            if (RawPath != null && File.Exists(Path.Combine(Environment.ExpandEnvironmentVariables(RawPath), Exe)))
                file = Path.Combine(Environment.ExpandEnvironmentVariables(RawPath), Exe);
            else if (ExistsInPath(Exe) || File.Exists(Environment.ExpandEnvironmentVariables(Exe)))
                file = Environment.ExpandEnvironmentVariables(Exe);

            if (file == null)
                throw new FileNotFoundException($"Executable not found.");

            if (RunAs == Privilege.TrustedInstaller)
                RunAsProcess(file, output);
            else
                RunAsPrivilegedProcess(file, output);

            InProgress = false;
            return;
        }
        [YamlMember(typeof(Privilege), Alias = "runas")]
        public Privilege RunAs { get; set; } = Privilege.TrustedInstaller;
        
        [YamlMember(typeof(string), Alias = "path")]
        public string RawPath { get; set; } = null;
       
        [YamlMember(typeof(string), Alias = "exe")]
        public string Exe { get; set; } 

        [YamlMember(typeof(string), Alias = "args")]
        public string? Arguments { get; set; }

        [YamlMember(typeof(bool), Alias = "baseDir")]
        public bool BaseDir { get; set; } = false;
        
        [YamlMember(typeof(bool), Alias = "exeDir")]
        public bool ExeDir { get; set; } = false;

        [YamlMember(typeof(bool), Alias = "createWindow")]
        public bool CreateWindow { get; set; } = false;
        
        [YamlMember(typeof(bool), Alias = "showOutput")]
        public bool ShowOutput { get; set; } = true;
        
        [YamlMember(typeof(bool), Alias = "showError")]
        public bool ShowError { get; set; } = true;
        
        [YamlMember(typeof(int), Alias = "timeout")]
        public int? Timeout { get; set; }

        [YamlMember(typeof(string), Alias = "wait")]
        public bool Wait { get; set; } = true;

        [YamlMember(typeof(Dictionary<string, ExitCodeAction>), Alias = "handleExitCodes")]
        [CanBeNull] public Dictionary<string, ExitCodeAction> HandleExitCodes { get; set; } = null;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 5;
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => false;

        private bool InProgress { get; set; } = false;
        public void ResetProgress() => InProgress = false;
        private bool HasExited { get; set; } = false;
        //public int ExitCode { get; set; }
        
        public string ErrorString() => String.IsNullOrEmpty(Arguments) ? $"RunAction failed to execute '{Exe}'." : $"RunAction failed to execute '{Exe}' with arguments '{Arguments}'.";
        
        public static bool ExistsInPath(string fileName)
        {
            if (File.Exists(fileName))
                return true;

            var values = Environment.GetEnvironmentVariable("PATH");
            foreach (var path in values.Split(Path.PathSeparator))
            {
                var fullPath = Path.Combine(path, fileName);
                if (File.Exists(fullPath))
                    return true;
                if (!fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(fullPath + ".exe"))
                    return true;
            }
            return false;
        }
        
        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return HasExited || !Wait ?  UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }

        public Task<bool> RunTask(Output.OutputWriter output)
        {
            return null;
        }

        private void RunAsProcess(string file, Output.OutputWriter output)
        {
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = !this.CreateWindow,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Normal,
                RedirectStandardError = ShowError,
                RedirectStandardOutput = ShowOutput,
                FileName = file,
            };
            if (Arguments != null) startInfo.Arguments = Environment.ExpandEnvironmentVariables(Arguments);

            if (ExeDir) startInfo.WorkingDirectory = AmeliorationUtil.Playbook.Path + "\\Executables";
            if (!Wait)
            {
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.UseShellExecute = true;
            }

            using var exeProcess = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            using (var handler = new OutputHandler("Process", exeProcess, output))
            {
                handler.StartProcess();
             
                if (!Wait)
                {
                    return;
                }
                
                if (Timeout.HasValue)
                {
                    var exited = exeProcess.WaitForExit(Timeout.Value);
                    if (!exited)
                    {
                        handler.CancelReading();
                        exeProcess.Kill();
                        throw new TimeoutException($"Executable run timeout exceeded.");
                    }
                }
                else
                {
                    bool exited = exeProcess.WaitForExit(30000);

                    // WaitForExit alone seems to not be entirely reliable
                    while (!exited && ExeRunning(exeProcess.ProcessName, exeProcess.Id))
                    {
                        exited = exeProcess.WaitForExit(30000);
                    }
                }
            }

            int exitCode = Wrap.ExecuteSafe(() => exeProcess.ExitCode, true, output.LogOptions).Value;
            if (exitCode != 0)
                output.WriteLineSafe("Info", $"Process exited with a non-zero exit code: {exitCode}");

            HasExited = true;
            
            if (HandleExitCodes != null)
            {
                foreach (string key in HandleExitCodes.Keys)
                {
                    if (IsApplicableNumber(key, exitCode))
                    {
                        throw new ErrorHandlingException(HandleExitCodes[key], $"Process '{Exe}' exit code {exitCode} handled with filter '{key}' --> {HandleExitCodes[key]}.");
                    }
                }
            }
        }
        private void RunAsPrivilegedProcess(string file, Output.OutputWriter output)
        {
            var startInfo = new AugmentedProcess.ProcessStartInfo
            {
                CreateNoWindow = !this.CreateWindow,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Normal,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                FileName = file,
            };
            if (Arguments != null) startInfo.Arguments = Arguments;

            if (ExeDir) startInfo.WorkingDirectory = AmeliorationUtil.Playbook.Path + "\\Executables";
            if (!Wait)
            {
                startInfo.RedirectStandardError = false;
                startInfo.RedirectStandardOutput = false;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.UseShellExecute = true;
            }

            if (!ShowOutput)
                startInfo.RedirectStandardOutput = false;
            if (!ShowError)
                startInfo.RedirectStandardError = false;

            using var exeProcess = new AugmentedProcess.Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            using (var handler = new OutputHandler("Process", exeProcess, output))
            {
                handler.StartProcess(RunAs);
             
                if (!Wait)
                {
                    return;
                }
                
                if (Timeout.HasValue)
                {
                    var exited = exeProcess.WaitForExit(Timeout.Value);
                    if (!exited)
                    {
                        handler.CancelReading();
                        exeProcess.Kill();
                        throw new TimeoutException($"Executable run timeout exceeded.");
                    }
                    
                    
                }
                else
                {
                    bool exited = exeProcess.WaitForExit(30000);

                    // WaitForExit alone seems to not be entirely reliable
                    while (!exited && ExeRunning(exeProcess.ProcessName, exeProcess.Id))
                    {
                        exited = exeProcess.WaitForExit(30000);
                    }
                }
            }

            int exitCode = Wrap.ExecuteSafe(() => exeProcess.ExitCode, true, output.LogOptions).Value;
            if (exitCode != 0)
                output.WriteLineSafe("Info", $"Process exited with a non-zero exit code: {exeProcess.ExitCode}");

            HasExited = true;
        }
        
        private static bool ExeRunning(string name, int id)
        {
            try
            {
                return Process.GetProcessesByName(name).Any(x => x.Id == id);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
