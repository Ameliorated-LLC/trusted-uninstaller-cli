using System.Collections.Generic;

namespace TrustedUninstaller.Shared.Tasks
{
    public class TaskList
    {
        public List<UninstallTask> uninstallTasks { get; set; } = new List<UninstallTask> { };
    }
}
