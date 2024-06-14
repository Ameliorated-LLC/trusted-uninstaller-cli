using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Core.Exceptions;
using YamlDotNet.Serialization;

namespace Core.Actions
{
    public class CmdAction : ICoreAction
    {
        [YamlMember(typeof(string), Alias = "command")]
        public string Command { get; set; }
        
        [YamlMember(typeof(string), Alias = "timeout")]
        public int? Timeout { get; set; }
        
        [YamlMember(typeof(string), Alias = "wait")]
        public bool Wait { get; set; } = true;
        
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
        
        public void RunTask(bool logExceptions = true)
        {
            ExitCode = null;

            RunAsProcess();
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

            }
            
            if (exitCode != 0)
            {
                StandardError = error.ToString();
                
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
        
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {

        }
    }
}
