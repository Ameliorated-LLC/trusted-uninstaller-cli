using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class CmdAction : TaskAction, ITaskAction
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
        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another Cmd action was called while one was in progress.");
            InProgress = true;
            
            Console.WriteLine($"Running cmd command '{Command}'...");
            
            ExitCode = null;

            var process = new Process();
            var startInfo = new ProcessStartInfo
            {
                WindowStyle = ProcessWindowStyle.Normal,
                FileName = "cmd.exe",
                Arguments = "/C " + $"\"{Environment.ExpandEnvironmentVariables(this.Command)}\"",
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
            process.Dispose();

            InProgress = false;
            return true;
        }

        private static void ProcOutputHandler(object sendingProcess,
         DataReceivedEventArgs outLine)
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
