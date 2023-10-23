using System;
using System.Linq;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace TrustedUninstaller.Shared.Actions
{
    // Integrate ame-assassin later
    internal class SystemPackageAction : TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread() { throw new NotImplementedException(); }
        public enum Architecture
        {
            amd64 = 0,
            wow64 = 1,
            msil = 2,
            x86 = 3,
            All = 4
        }
        
        [YamlMember(typeof(string), Alias = "name")]
        public string Name { get; set; }

        [YamlMember(typeof(string), Alias = "arch")]
        public Architecture Arch { get; set; } = Architecture.All;

        [YamlMember(typeof(string), Alias = "language")]
        public string Language { get; set; } = "*";

        [YamlMember(typeof(string), Alias = "regexExcludeFiles")]
        public string[]? RegexExcludeList { get; set; }
        [YamlMember(typeof(string), Alias = "excludeDependents")]
        public string[]? ExcludeDependentsList { get; set; }

        [YamlMember(typeof(string[]), Alias = "weight")]
        public int ProgressWeight { get; set; } = 15;
        public int GetProgressWeight() => ProgressWeight;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"SystemPackageAction failed to remove '{Name}'.";
        
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress) return UninstallTaskStatus.InProgress;
            return HasFinished ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }
        private bool HasFinished = false;
        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another Appx action was called while one was in progress.");
            InProgress = true;

            Console.WriteLine($"Removing system package '{Name}'...");

            var excludeArgs = new StringBuilder("");
            if (RegexExcludeList != null)
            {
                foreach (var regex in RegexExcludeList)
                {
                    excludeArgs.Append(@$" -xf ""{regex}""");
                }
            }
            
            var excludeDependsArgs = new StringBuilder("");
            if (ExcludeDependentsList != null)
            {
                foreach (var dependent in ExcludeDependentsList)
                {
                    excludeDependsArgs.Append(@$" -xdependent ""{dependent}""");
                }
            }

            string kernelDriverArg = AmeliorationUtil.UseKernelDriver ? " -UseKernelDriver" : "";

            var psi = new ProcessStartInfo()
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                Arguments = $@"-SystemPackage ""{Name}"" -Arch {Arch.ToString()} -Language ""{Language}""" + excludeArgs + excludeDependsArgs + kernelDriverArg,
                FileName = Directory.GetCurrentDirectory() + "\\ame-assassin\\ame-assassin.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            var proc = Process.Start(psi);
            
            proc.OutputDataReceived += ProcOutputHandler;
            proc.ErrorDataReceived += ProcOutputHandler;
                
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            
            bool exited = proc.WaitForExit(30000);
                    
            // WaitForExit alone seems to not be entirely reliable
            while (!exited && ExeRunning(proc))
            {
                exited = proc.WaitForExit(30000);
            }
            
            using (var log = new StreamWriter("Logs\\Packages.txt", true))
                log.Write(output.ToString());
            
            HasFinished = true;

            InProgress = false;
            return true;
        }
        
        private StringBuilder output = new StringBuilder("");
        private bool PleaseWait = false;
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            var write = outLine == null ? "" : outLine.Data;
            output.Append(write + Environment.NewLine);
            
            if (String.IsNullOrEmpty(write)) return;
            
            if (write.StartsWith("--- Removing"))
            {
                Console.WriteLine(write.Substring(4, write.Length - 4));
                PleaseWait = true;
            }
            if (write.StartsWith("Waiting for the service to stop...") && PleaseWait)
            {
                PleaseWait = false;
                Console.WriteLine("This may take some time...");
            }
        }
        
        private static bool ExeRunning(Process process)
        {
            try
            {
                return Process.GetProcessesByName(process.ProcessName).Any(x => x.Id == process.Id);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
