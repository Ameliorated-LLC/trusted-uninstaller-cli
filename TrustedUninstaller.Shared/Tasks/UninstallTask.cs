using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using JetBrains.Annotations;
using TrustedUninstaller.Shared.Parser;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Tasks
{
    public enum PreviousOption
    {
        Ignore,
        
    }
    public class UninstallTask
    {
        public string Title { get; set; }
#nullable enable
        public string? Description { get; set; }

        public int? MinVersion { get; set; }
        public int? MaxVersion { get; set; }
#nullable disable
        public UninstallTaskStatus Status { get; set; } = UninstallTaskStatus.ToDo;
        
        public List<ITaskAction> Actions { get; set; } = new List<ITaskAction>();

        public int Priority { get; set; } = 1;
        public UninstallTaskPrivilege Privilege { get; set; } = UninstallTaskPrivilege.Admin;

        [YamlMember(typeof(string), Alias = "option")]
        public string Option { get; set; } = null;
        [YamlMember(typeof(string[]), Alias = "options")]
        public string[] Options { get; set; } = null;
        [YamlMember(typeof(string[]), Alias = "builds")]
        public string[] Builds { get; set; } = null;
        [YamlMember(typeof(string), Alias = "cpuArch")]
        public string Arch { get; set; } = null;
        
        [YamlMember(typeof(bool?), Alias = "onUpgrade")]
        public bool? OnUpgrade { get; set; } = null;
        
        [YamlMember(typeof(string[]), Alias = "onUpgradeVersions")]
        public string[] OnUpgradeVersions { get; set; } = null;
        
        [YamlMember(typeof(string), Alias = "previousOption")]
        [CanBeNull] public string PreviousOption { get; set; } = null;
        
        public List<string> Features { get; set; } = new List<string>();

        public List<string> Tasks
        {
            set => Features = value;
            get => Features;
        }

        public void Update()
        {
            /*
            var statusList = Actions.Select(entry => entry.GetStatus()).ToList();
            if (statusList.Any(entry => entry == UninstallTaskStatus.InProgress))
            {
                Status = UninstallTaskStatus.InProgress;

            }
            else if (statusList.All(entry => entry == UninstallTaskStatus.Completed))
            {
                Status = UninstallTaskStatus.Completed;
            }
            else
            {
                Status = UninstallTaskStatus.ToDo;
            }
            */
        }

    }
}
