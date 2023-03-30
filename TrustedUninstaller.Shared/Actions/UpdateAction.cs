using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    internal class UpdateAction : ITaskAction
    {
        [YamlMember(typeof(string), Alias = "name")]
        public string PackageName { get; set; }
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"UpdateAction failed to remove update package {PackageName}.";
        
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return UninstallTaskStatus.Completed;
        }

        public async Task<bool> RunTask()
        {
            if (InProgress)
            {
                Console.WriteLine("An update action is already in progress...");
                return false;
            }
            InProgress = true;
            
            Console.WriteLine($"Removing update package '{PackageName}'...");
            
            CmdAction removeUpdate = new CmdAction()
            {
                Command = @$"DISM.exe /Online /Remove-Package /PackageName:{PackageName} /quiet /norestart"
            };

            while(removeUpdate.GetStatus() != UninstallTaskStatus.Completed)
            {
                await removeUpdate.RunTask();
            }

            InProgress = false;
            return true;
            
        }
    }
}
