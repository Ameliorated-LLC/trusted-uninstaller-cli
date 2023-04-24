using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.TaskScheduler;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    internal enum ScheduledTaskOperation
    {
        Delete = 0,
        Enable = 1,
        Disable = 2,
        DeleteFolder = 3
    }

    internal class ScheduledTaskAction : ITaskAction
    {
        [YamlMember(typeof(ScheduledTaskOperation), Alias = "operation")]
        public ScheduledTaskOperation Operation { get; set; } = ScheduledTaskOperation.Delete;
        [YamlMember(Alias = "data")]
        public string? RawTask { get; set; } = null;
        [YamlMember(Alias = "path")]
        public string Path { get; set; }

        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;

        private bool InProgress { get; set; } = false;
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"ScheduledTaskAction failed to change task {Path} to state {Operation.ToString()}";

        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }
            
            using TaskService ts = new TaskService();

            if (Operation != ScheduledTaskOperation.DeleteFolder)
            {
                var task = ts.GetTask(Path);
                if (task is null)
                {
                    return Operation == ScheduledTaskOperation.Delete ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
                }

                if (task.Enabled)
                {
                    return Operation == ScheduledTaskOperation.Enable ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
                }

                return Operation == ScheduledTaskOperation.Disable ?
                    UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            }
            else
            {
                var folder = ts.GetFolder(Path);
                if (folder == null)
                    return UninstallTaskStatus.Completed;
                
                return folder.GetTasks().Any() ? UninstallTaskStatus.ToDo : UninstallTaskStatus.Completed;
            }
        }

        public async Task<bool> RunTask()
        {
            if (GetStatus() == UninstallTaskStatus.Completed)
            {
                return true;
            }

            if (InProgress) throw new TaskInProgressException("Another ScheduledTask action was called while one was in progress.");

            Console.WriteLine($"{Operation.ToString().TrimEnd('e')}ing scheduled task '{Path}'...");

            using TaskService ts = new TaskService();

            InProgress = true;

            if (Operation != ScheduledTaskOperation.DeleteFolder)
            {

                var task = ts.GetTask(Path);
                if (task is null)
                {
                    if (Operation == ScheduledTaskOperation.Delete)
                    {
                        return true;
                    }

                    if (RawTask is null || RawTask.Length == 0)
                    {
                        return false;
                    }
                }

                switch (Operation)
                {
                    case ScheduledTaskOperation.Delete:
                        // TODO: This will probably not work if we actually use sub-folders
                        ts.RootFolder.DeleteTask(Path);
                        break;
                    case ScheduledTaskOperation.Enable:
                    case ScheduledTaskOperation.Disable:
                        {
                            if (task is null && !(RawTask is null))
                            {
                                task = ts.RootFolder.RegisterTask(Path, RawTask);
                            }

                            if (!(task is null))
                            {
                                task.Enabled = Operation == ScheduledTaskOperation.Enable;
                            }
                            else
                            {
                                throw new ArgumentException($"Task provided is null.");
                            }

                            break;
                        }
                    default:
                        throw new ArgumentException($"Argument out of range.");
                }

                InProgress = false;
                return true;
            }
            else
            {
                var folder = ts.GetFolder(Path);

                if (folder is null) return true;
                
                folder.GetTasks().ToList().ForEach(x => folder.DeleteTask(x.Name));

                try
                {
                    folder.Parent.DeleteFolder(folder.Name);
                }
                catch (Exception e)
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "Error removing task folder.", folder.Name);
                }

                InProgress = false;
                return true;
            }
        }
    }
}
