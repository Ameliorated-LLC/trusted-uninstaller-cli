using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Core;

namespace TrustedUninstaller.Shared.Tasks
{
    public enum Scope
    {
        AllUsers = 0,
        CurrentUser = 1,
        ActiveUsers = 2,
        DefaultUser = 3
    }
    
    public interface ITaskAction
    {
        public ErrorAction GetDefaultErrorAction();
        public bool GetRetryAllowed();
        public int GetProgressWeight();
        public void ResetProgress();
        public string ErrorString();
        public UninstallTaskStatus GetStatus(Output.OutputWriter output);
        public Task<bool> RunTask(Output.OutputWriter output);
        public void RunTaskOnMainThread(Output.OutputWriter output);
    }
}