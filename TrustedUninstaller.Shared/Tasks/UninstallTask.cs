using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using TrustedUninstaller.Shared.Parser;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Tasks
{
    public class UninstallTask
    {
        public string Title { get; set; }
#nullable enable
        public string? Description { get; set; }

        public string[]? SupportedBuilds { get; set; }
        
        public int? MinVersion { get; set; }
        public int? MaxVersion { get; set; }
#nullable disable
        public UninstallTaskStatus Status { get; set; } = UninstallTaskStatus.ToDo;
        public List<ITaskAction> Actions { get; set; }

        public int Priority { get; set; } = 1;
        public UninstallTaskPrivilege Privilege { get; set; } = UninstallTaskPrivilege.Admin;
        public List<string> Features { get; set; } = new List<string>();

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

        public override string ToString()
        {
            var sb = new StringBuilder();
            var sw = new StringWriter(sb);

            var parser = new ConfigParser();
            parser.SerializeItem(sw, this);
            return sb.ToString();
        }
    }
}
