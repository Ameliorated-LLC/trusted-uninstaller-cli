using System;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class WriteStatusAction : ITaskAction
    {
        [YamlMember(typeof(string), Alias = "status")]
        public string Status { get; set; }
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        public string ErrorString() => "";
        public int GetProgressWeight() => 0;
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            return hasCompleted ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }
        private bool hasCompleted;
        public async Task<bool> RunTask()
        {
            if (String.IsNullOrEmpty(Status))
            {
                Console.WriteLine(":AME-STATUS: " + "Running actions");
            }
            else
            {
                Console.WriteLine(":AME-STATUS: " + Status);
            }

            hasCompleted = true;
            return true;
        }
    }
}
