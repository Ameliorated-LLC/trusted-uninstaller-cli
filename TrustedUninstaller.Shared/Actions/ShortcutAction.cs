using System;
using System.IO;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using IWshRuntimeLibrary;
using File = System.IO.File;

namespace TrustedUninstaller.Shared.Actions
{
    class ShortcutAction : ITaskAction
    {
        [YamlMember(typeof(string), Alias = "path")]
        public string RawPath { get; set; }

        [YamlMember(typeof(string), Alias = "name")]
        public string Name { get; set; }

        [YamlMember(typeof(string), Alias = "destination")]
        public string Destination { get; set; }

        [YamlMember(typeof(string), Alias = "description")]
        public string Description { get; set; }
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"ShortcutAction failed to create shortcut to '{Destination}' from '{RawPath}' with name {Name}.";
        
        public UninstallTaskStatus GetStatus()
        {
            //If the shortcut already exists return Completed
            return File.Exists(Path.Combine(this.Destination, this.Name + ".lnk")) ? 
                UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }

        public async Task<bool> RunTask()
        {
            RawPath = Environment.ExpandEnvironmentVariables(RawPath);
            Console.WriteLine($"Creating shortcut from '{Destination}' to '{RawPath}'...");
            
            if (File.Exists(this.RawPath))
            {

                WshShell shell = new WshShell();
                var sc = (IWshShortcut)shell.CreateShortcut(Path.Combine(this.Destination, this.Name + ".lnk"));
                sc.Description = this.Description;
                sc.TargetPath = this.RawPath;
                sc.Save();
            }
            else
            {
                throw new FileNotFoundException($"File '{RawPath}' not found.");
            }
            
            return true;
        }
    }
}
