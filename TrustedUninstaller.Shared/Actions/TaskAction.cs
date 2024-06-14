using System;
using System.Threading.Tasks;
using Core;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    public class TaskAction : Tasks.TaskAction, ITaskAction
    {
        [YamlMember(typeof(string), Alias = "path")]
        public string Path { get; set; }
        
        public void RunTaskOnMainThread(Output.OutputWriter output) => throw new NotImplementedException();
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        public string ErrorString() => "";
        public int GetProgressWeight() => 0;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => false;
        public UninstallTaskStatus GetStatus(Output.OutputWriter output) => throw new NotImplementedException();
        public Task<bool> RunTask(Output.OutputWriter output) => throw new NotImplementedException();

    }
}
