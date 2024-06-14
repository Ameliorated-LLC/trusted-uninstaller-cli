using System;
using System.Linq;
using System.Threading.Tasks;
//using Windows.ApplicationModel;
//using Windows.Management.Deployment;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Core;

namespace TrustedUninstaller.Shared.Actions
{
    // Integrate ame-assassin later
    internal class AppxAction : Tasks.TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        
        public enum AppxOperation
        {
            Remove = 0,
            ClearCache = 1,
        }
        public enum Level
        {
            Family = 0,
            Package = 1,
            App = 2
        }
        
        [YamlMember(typeof(string), Alias = "name")]
        public string Name { get; set; }

        [YamlMember(typeof(Level), Alias = "type")]
        public Level? Type { get; set; } = Level.Family;
        
        [YamlMember(typeof(AppxOperation), Alias = "operation")]
        public AppxOperation Operation { get; set; } = AppxOperation.Remove;
        [YamlMember(typeof(bool), Alias = "verboseOutput")]
        public bool Verbose { get; set; } = false;
        
        [YamlMember(typeof(bool), Alias = "unregister")]
        public bool Unregister { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 30;
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => false;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"AppxAction failed to remove '{Name}'.";
        
        /*
        private Package GetPackage()
        {
            var packageManager = new PackageManager();

            return packageManager.FindPackages().FirstOrDefault(package => package.Id.Name == Name);
        }
        */
        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            if (InProgress) return UninstallTaskStatus.InProgress;
            return HasFinished ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            //return GetPackage() == null ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }
        private bool HasFinished = false;
        public async Task<bool> RunTask(Output.OutputWriter output)
        {
            if (InProgress) throw new TaskInProgressException("Another Appx action was called while one was in progress.");
            InProgress = true;

            output.WriteLineSafe("Info", $"Removing APPX {Type.ToString().ToLower()} '{Name}'...");
            
            WinUtil.CheckKph();

            string verboseArg = Verbose ? " -Verbose" : "";
            string unregisterArg = Unregister ? " -Verbose" : "";
            string kernelDriverArg = AmeliorationUtil.UseKernelDriver ? " -UseKernelDriver" : "";
            
            var psi = new ProcessStartInfo()
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                Arguments = $@"-{Type.ToString()} ""{Name}""" + verboseArg + unregisterArg + kernelDriverArg,
                FileName = Directory.GetCurrentDirectory() + "\\ame-assassin\\ame-assassin.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            if (Operation == AppxOperation.ClearCache)
            {
                psi.Arguments = $@"-ClearCache ""{Name}""";
            }

            this.outputWriter = output;
            
            var proc = Process.Start(psi);
            
            proc.OutputDataReceived += ProcOutputHandler;
            proc.ErrorDataReceived += ProcOutputHandler;
                
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            
            bool exited = proc.WaitForExit(30000);
                    
            // WaitForExit alone seems to not be entirely reliable
            while (!exited && ExeRunning("ame-assassin", proc.Id))
            {
                exited = proc.WaitForExit(30000);
            }

            HasFinished = true;

            InProgress = false;
            return true;
        }

        private Output.OutputWriter outputWriter = null;
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            if (!string.IsNullOrWhiteSpace(outLine.Data))
                outputWriter.WriteLineSafe("Process", outLine.Data);
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
