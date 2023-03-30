using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace TrustedUninstaller.Shared
{
    public class Playbook
    {
        public string Name { get; set; }
        public string ShortDescription { get; set; }
        public string Description { get; set; }
        
        public string Title { get; set; }
        public string Username { get; set; }
        public string Details { get; set; }
        public string Version { get; set; }

        public string ProgressText { get; set; } = "Deploying the selected Playbook configuration onto the system.";
        public int EstimatedMinutes { get; set; } = 25;
        
#nullable enable
        public string[]? SupportedBuilds { get; set; }
        public Requirements.Requirement[]? Requirements { get; set; }
        public string? Git { get; set; }
        public string? DonateLink { get; set; }
        public string? Website { get; set; }
        public string? ProductCode { get; set; }
        public string? PasswordReplace { get; set; }
#nullable disable

        public string Path { get; set; }
        
        public override string ToString()
        {
            return $"Name: {Name}\nDescription: {Description}\nUsername: {Username}\nDetails: {Details}\nRequirements: {Requirements}."; 
        }
    }
}
