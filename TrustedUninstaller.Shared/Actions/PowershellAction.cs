using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class PowerShellAction : ITaskAction
    {
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
        
        
        private int? ExitCode { get; set; }
        public string? StandardError { get; set; }
        public string StandardOutput { get; set; }
        
        public int GetProgressWeight() => ProgressWeight;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"PowerShellAction failed to run command '{Command}'.";
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return ExitCode == null ? UninstallTaskStatus.ToDo: UninstallTaskStatus.Completed;
        }

        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another Powershell action was called while one was in progress.");
            InProgress = true;
            
            Console.WriteLine($"Running PowerShell command '{Command}'...");

            var process = new Process();
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
            if (ExeDir) startInfo.WorkingDirectory = Directory.GetCurrentDirectory() + "\\Executables";
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
                return true;
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
                
            else process.WaitForExit();
                
            StandardError = error.ToString();
            if (process.ExitCode != 0)
            {
                Console.WriteLine($"PowerShell instance exited with error code: {process.ExitCode}");
                if (!String.IsNullOrEmpty(StandardError)) Console.WriteLine($"Error message: {StandardError}");

                ErrorLogger.WriteToErrorLog("PowerShell exited with a non-zero exit code: " + process.ExitCode, null, "PowerShellAction Error", Command);
                
                this.ExitCode = process.ExitCode;
            }
            else
            {
                if (!String.IsNullOrEmpty(StandardError)) Console.WriteLine($"Error output: {StandardError}");
                ExitCode = 0;
            }
            
            process.CancelOutputRead();
            process.CancelErrorRead();
            process.Dispose();
                
            InProgress = false;
            return true;
        }

        private static void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            if (!String.IsNullOrEmpty(outLine.Data))
            {
                Console.WriteLine(outLine.Data);
            }
            else
            {
                Console.WriteLine();
            }
        }
    }
}
