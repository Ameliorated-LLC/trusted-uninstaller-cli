using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Documents;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public enum Privilege
    {
        TrustedInstaller,
        System,
        CurrentUserElevated,
        CurrentUser,
    }
    
    public class RunAction : TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread()
        {
            if (RawPath != null) RawPath = Environment.ExpandEnvironmentVariables(RawPath);
            InProgress = true;

            var privilegeText = RunAs == Privilege.CurrentUser ? " as the current user" : RunAs == Privilege.CurrentUserElevated ? " as the current user elevated" : RunAs == Privilege.System ?
                " as the system account" : "";
            
            if (Arguments == null) Console.WriteLine($"Running '{Exe + privilegeText}'...");
            else Console.WriteLine($"Running '{Exe}' with arguments '{Arguments + privilegeText}'...");

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
                RunAsProcess(file);
            else
                RunAsPrivilegedProcess(file);

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

        public Task<bool> RunTask()
        {
            return null;
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

            int exitCode = 0;
            try
            {
                exitCode = exeProcess.ExitCode;
            }
            catch (Exception ex)
            {
                ErrorLogger.WriteToErrorLog("Error fetching process exit code. (1)", null, "RunAction Error", Exe + " " + Arguments);
            }
            if (exitCode != 0)
            {
                ErrorLogger.WriteToErrorLog("Process exited with a non-zero exit code: " + exitCode, null, "RunAction Error", Exe + " " + Arguments);
            }

            HasExited = true;

            if (ShowOutput)
                exeProcess.CancelOutputRead();
            if (ShowError)
                exeProcess.CancelErrorRead();
            
            exeProcess.Dispose();
        }
        private void RunAsPrivilegedProcess(string file)
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

            var exeProcess = new AugmentedProcess.Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            ProcessPrivilege.StartPrivilegedTask(exeProcess, RunAs);

            if (!Wait)
            {
                exeProcess.Dispose();
                return;
            }

            if (ShowOutput)
                exeProcess.OutputDataReceived += PrivilegedProcOutputHandler;
            if (ShowError)
                exeProcess.ErrorDataReceived += PrivilegedProcOutputHandler;

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

            try
            {
                if (exeProcess.ExitCode != 0)
                {
                    ErrorLogger.WriteToErrorLog("Process exited with a non-zero exit code: " + exeProcess.ExitCode, null, "RunAction Error", Exe + " " + Arguments);
                }
            }
            catch (Exception ex)
            {
                ErrorLogger.WriteToErrorLog("Error fetching process exit code. (1)", null, "RunAction Error", Exe + " " + Arguments);
                
                Thread.Sleep(500);
                try
                {
                    if (exeProcess.ExitCode != 0)
                    {
                        ErrorLogger.WriteToErrorLog("Process exited with a non-zero exit code: " + exeProcess.ExitCode, null, "RunAction Error", Exe + " " + Arguments);
                    }
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog("Error fetching process exit code. (2)", null, "RunAction Error", Exe + " " + Arguments);
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

        private void PrivilegedProcOutputHandler(object sendingProcess, AugmentedProcess.DataReceivedEventArgs outLine)
        {
            try
            {
                // Collect the sort command output. 
                if (!String.IsNullOrEmpty(outLine.Data))
                {
                    var outputString = outLine.Data;

                    if (outputString.Contains("\\AME"))
                    {
                        outputString = outputString.Substring(outputString.IndexOf('>') + 1);
                    }
                    Console.WriteLine(outputString);
                    Output += outputString + Environment.NewLine;
                }
                else
                {
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("Error processing process output", e.StackTrace, "RunAction Error", Exe);
            }
        }
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            try
            {
                // Collect the sort command output. 
                if (!String.IsNullOrEmpty(outLine.Data))
                {
                    var outputString = outLine.Data;

                    if (outputString.Contains("\\AME"))
                    {
                        outputString = outputString.Substring(outputString.IndexOf('>') + 1);
                    }
                    Console.WriteLine(outputString);
                    Output += outputString + Environment.NewLine;
                }
                else
                {
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog("Error processing process output", e.StackTrace, "RunAction Error", Exe);
            }
        }
    }
}
