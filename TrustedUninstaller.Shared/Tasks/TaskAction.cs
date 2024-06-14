using System.Globalization;
using JetBrains.Annotations;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Tasks
{    
    public enum ErrorAction
    {
        Ignore,
        Log,
        Notify,
        Halt,
    }

    public abstract class TaskAction
    {
        public enum ExitCodeAction
        {
            Log,
            Retry,
            Error,
            RetryError,
            Halt,
        }
        
        [YamlMember(typeof(bool), Alias = "ignoreErrors")]
        public bool IgnoreErrors { get; set; } = false;
        
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
        
        [YamlMember(typeof(ErrorAction), Alias = "errorAction")]
        public ErrorAction? ErrorAction { get; set; } = null;
        [YamlMember(typeof(bool), Alias = "allowRetries")]
        public bool? AllowRetries { get; set; } = null;

        protected bool IsApplicableNumber(string number, int value)
        {
            bool negative = false;
            number = number.Trim();
            if (number.StartsWith("!"))
            {
                number = number.TrimStart('!');
                negative = true;
            }
            bool result = false;

            if (number.StartsWith(">="))
            {
                var parsed = int.Parse(number.Substring(2), CultureInfo.InvariantCulture);
                if (value >= parsed)
                    result = true;
            }
            else if (number.StartsWith("<="))
            {
                var parsed = int.Parse(number.Substring(2), CultureInfo.InvariantCulture);
                if (value <= parsed)
                    result = true;
            }
            else if (number.StartsWith(">"))
            {
                var parsed = int.Parse(number.Substring(1), CultureInfo.InvariantCulture);
                if (value > parsed)
                    result = true;
            }
            else if (number.StartsWith("<"))
            {
                var parsed = int.Parse(number.Substring(1), CultureInfo.InvariantCulture);
                if (value < parsed)
                    result = true;
            }
            else
            {
                var parsed = int.Parse(number, CultureInfo.InvariantCulture);
                if (value == parsed)
                    result = true;
            }

            return negative ? !result : result;
        }
    }
}
