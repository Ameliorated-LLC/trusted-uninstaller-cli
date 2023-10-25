using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class CmdAction : TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread()
        {
            if (InProgress) throw new TaskInProgressException("Another Cmd action was called while one was in progress.");
            InProgress = true;
            
            var privilegeText = RunAs == Privilege.CurrentUser ? " as the current user" : RunAs == Privilege.CurrentUserElevated ? " as the current user elevated" : RunAs == Privilege.System ?
                " as the system account" : "";
            
            Console.WriteLine($"Running cmd command '{Command}'{privilegeText}...");

            ExitCode = null;
            
            if (RunAs == Privilege.TrustedInstaller)
                RunAsProcess();
            else
                RunAsPrivilegedProcess();

            InProgress = false;
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
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        
        public int GetProgressWeight() => ProgressWeight;

        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        private int? ExitCode { get; set; }

        public string? StandardError { get; set; }

        public string StandardOutput { get; set; }

        public string ErrorString() => $"CmdAction failed to run command '{Command}'.";
        
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return ExitCode == null ? UninstallTaskStatus.ToDo: UninstallTaskStatus.Completed;
        }
        
        public Task<bool> RunTask()
        {
            return null;
        }

        private void RunAsProcess()
        {
            var process = new Process();
            var startInfo = new ProcessStartInfo
            {
                WindowStyle = ProcessWindowStyle.Normal,
                FileName = "cmd.exe",
                Arguments = "/C " + $"\"{this.Command}\"",
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
            process.Start();
                
            if (!Wait)
            {
                process.Dispose();
                return;
            }
            
            var error = new StringBuilder();
            process.OutputDataReceived += ProcOutputHandler;
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs args)
            {
                if (!String.IsNullOrEmpty(args.Data))
                    error.AppendLine(args.Data);
                else
                    error.AppendLine();
            };
            
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (Timeout != null)
            {
                var exited = process.WaitForExit(Timeout.Value);
                if (!exited)
                {
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
            
            int exitCode = 0;
            try
            {
                exitCode = process.ExitCode;
            }
            catch (Exception ex)
            {
                ErrorLogger.WriteToErrorLog("Error fetching process exit code. (1)", null, "CmdAction Error", Command);
            }
            
            if (exitCode != 0 && !Command.Contains("ProcessHacker\\x64\\ProcessHacker.exe"))
            {
                StandardError = error.ToString();
                Console.WriteLine($"cmd instance exited with error code: {exitCode}");
                if (!String.IsNullOrEmpty(StandardError)) Console.WriteLine($"Error message: {StandardError}");
                
                ErrorLogger.WriteToErrorLog("Cmd exited with a non-zero exit code: " + exitCode, null, "CmdAction Error", Command);
                
                this.ExitCode = exitCode;
            }
            else
            {
                ExitCode = 0;
            }
            
            process.CancelOutputRead();
            process.CancelErrorRead();
            process.Dispose();
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
        
        private void RunAsPrivilegedProcess()
        {
            
            var process = new AugmentedProcess.Process();
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
            ProcessPrivilege.StartPrivilegedTask(process, RunAs);
                
            if (!Wait)
            {
                process.Dispose();
                return;
            }
            
            var error = new StringBuilder();
            process.OutputDataReceived += PrivilegedProcOutputHandler;
            process.ErrorDataReceived += delegate(object sender, AugmentedProcess.DataReceivedEventArgs args)
            {
                if (!String.IsNullOrEmpty(args.Data))
                    error.AppendLine(args.Data);
                else
                    error.AppendLine();
            };
            
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (Timeout != null)
            {
                var exited = process.WaitForExit(Timeout.Value);
                if (!exited)
                {
                    process.Kill();
                    throw new TimeoutException($"Command '{Command}' timeout exceeded.");
                }
            }
                
            else process.WaitForExit();
                

            if (process.ExitCode != 0)
            {
                StandardError = error.ToString();
                Console.WriteLine($"cmd instance exited with error code: {process.ExitCode}");
                if (!String.IsNullOrEmpty(StandardError)) Console.WriteLine($"Error message: {StandardError}");
                
                ErrorLogger.WriteToErrorLog("Cmd exited with a non-zero exit code: " + process.ExitCode, null, "CmdAction Error", Command);
                
                this.ExitCode = process.ExitCode;
            }
            else
            {
                ExitCode = 0;
            }
            
            process.CancelOutputRead();
            process.CancelErrorRead();
            process.Dispose();
        }
        
        private void PrivilegedProcOutputHandler(object sendingProcess, AugmentedProcess.DataReceivedEventArgs outLine)
        {
            var outputString = outLine.Data;

            // Collect the sort command output. 
            if (!String.IsNullOrEmpty(outLine.Data))
            {
                if (outputString.Contains("\\AME"))
                {
                    outputString = outputString.Substring(outputString.IndexOf('>') + 1);
                }
                Console.WriteLine(outputString);
            }
            else
            {
                Console.WriteLine();
            }
        }
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            var outputString = outLine.Data;

            // Collect the sort command output. 
            if (!String.IsNullOrEmpty(outLine.Data))
            {
                if (outputString.Contains("\\AME"))
                {
                    outputString = outputString.Substring(outputString.IndexOf('>') + 1);
                }
                Console.WriteLine(outputString);
            }
            else
            {
                Console.WriteLine();
            }
        }
    }
}
