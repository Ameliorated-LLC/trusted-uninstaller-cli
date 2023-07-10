using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Tasks
{
    public class TaskAction
    {
        [YamlMember(typeof(bool), Alias = "ignoreErrors")]
        public bool IgnoreErrors { get; set; } = false;
        [YamlMember(typeof(string), Alias = "option")]
        public string Option { get; set; } = null;
        [YamlMember(typeof(string), Alias = "cpuArch")]
        public string Arch { get; set; } = null;
    }
}
