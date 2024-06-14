using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using YamlDotNet.Serialization;

namespace Core.Actions
{
    public class RunAction : ICoreAction
    {
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
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 5;
        public int GetProgressWeight() => ProgressWeight;

        private bool InProgress { get; set; } = false;
        public void ResetProgress() => InProgress = false;
        private bool HasExited { get; set; } = false;
        //public int ExitCode { get; set; }
        public string? Output { get; private set; }
        private string? StandardError { get; set; }
        
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
        
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return HasExited || !Wait ?  UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }

        public void RunTask(bool logExceptions = true)
        {
            if (RawPath != null) RawPath = Environment.ExpandEnvironmentVariables(RawPath);
            InProgress = true;
            
            var currentDir = Directory.GetCurrentDirectory();
            
            if (BaseDir) RawPath = currentDir;

            string file = null;
            if (RawPath != null && File.Exists(Path.Combine(Environment.ExpandEnvironmentVariables(RawPath), Exe)))
                file = Path.Combine(Environment.ExpandEnvironmentVariables(RawPath), Exe);
            else if (ExistsInPath(Exe) || File.Exists(Environment.ExpandEnvironmentVariables(Exe)))
                file = Environment.ExpandEnvironmentVariables(Exe);

            if (file == null)
                throw new FileNotFoundException($"Executable not found.");

            RunAsProcess(file);

            InProgress = false;
            return;
        }

        private void RunAsProcess(string file)
        {
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = !this.CreateWindow,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Normal,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                FileName = file,
            };
            if (Arguments != null) startInfo.Arguments = Environment.ExpandEnvironmentVariables(Arguments);

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

            var exeProcess = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            exeProcess.Start();

            if (!Wait)
            {
                exeProcess.Dispose();
                return;
            }

            if (ShowOutput)
                exeProcess.OutputDataReceived += ProcOutputHandler;
            if (ShowError)
                exeProcess.ErrorDataReceived += ProcOutputHandler;

            if (ShowOutput)
                exeProcess.BeginOutputReadLine();
            if (ShowError)
                exeProcess.BeginErrorReadLine();

            if (Timeout.HasValue)
            {
                var exited = exeProcess.WaitForExit(Timeout.Value);
                if (!exited)
                {
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

            HasExited = true;

            if (ShowOutput)
                exeProcess.CancelOutputRead();
            if (ShowError)
                exeProcess.CancelErrorRead();
            
            exeProcess.Dispose();
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

        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
        }
    }
}
