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

namespace TrustedUninstaller.Shared.Actions
{
    // Integrate ame-assassin later
    internal class AppxAction : TaskAction, ITaskAction
    {
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
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 30;
        public int GetProgressWeight() => ProgressWeight;
        
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
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress) return UninstallTaskStatus.InProgress;
            return HasFinished ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            //return GetPackage() == null ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }
        private bool HasFinished = false;
        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another Appx action was called while one was in progress.");
            InProgress = true;

            Console.WriteLine($"Removing APPX {Type.ToString().ToLower()} '{Name}'...");

            string verboseArg = Verbose ? " -Verbose" : "";
            
            var psi = new ProcessStartInfo()
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                Arguments = $@"-{Type.ToString()} ""{Name}""" + verboseArg,
                FileName = Directory.GetCurrentDirectory() + "\\ame-assassin\\ame-assassin.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            if (Operation == AppxOperation.ClearCache)
            {
                psi.Arguments = $@"-ClearCache ""{Name}""";
            }
            
            
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
        private void ProcOutputHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            var write = outLine.Data == null ? "" : outLine.Data;
            output.Append(write + Environment.NewLine);

            if (!write.Equals("Complete!")) Console.WriteLine(write);
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
