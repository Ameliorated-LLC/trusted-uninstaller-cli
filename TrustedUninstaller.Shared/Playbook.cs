using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Policy;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;
using System.Xml.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using MessageBox = System.Windows.MessageBox;

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
        
        [XmlArray]
        [XmlArrayItem(ElementName = "CheckboxPage", Type = typeof(CheckboxPage))]
        [XmlArrayItem(ElementName = "RadioPage", Type = typeof(RadioPage))]
        [XmlArrayItem(ElementName = "RadioImagePage", Type = typeof(RadioImagePage))]
        public FeaturePage[] FeaturePages { get; set; }

        public string ProgressText { get; set; } = "Deploying the selected Playbook configuration onto the system.";
        public int EstimatedMinutes { get; set; } = 25;
        
#nullable enable
        public string[]? SupportedBuilds { get; set; }
        public Requirements.Requirement[] Requirements { get; set; } = new Requirements.Requirement[] {};
        public string? Git { get; set; }
        public string? DonateLink { get; set; }
        public string? Website { get; set; }
        public string? ProductCode { get; set; }
        public string? PasswordReplace { get; set; }
#nullable disable
        public bool Overhaul { get; set; } = false;

        public string Path { get; set; }
        
        public bool? UseKernelDriver { get; set; } = null;

        public List<string> Options { get; set; } = null;

        public string Validate()
        {
            if (FeaturePages == null)
                return null;

            foreach (var rawPage in FeaturePages)
            {
                if (rawPage.GetType() == typeof(CheckboxPage))
                {
                    var page = (CheckboxPage)rawPage;

                    if (page.Options.Length > 2 && page.TopLine != null && page.BottomLine != null)
                        return @$"CheckboxPage with a TopLine and BottomLine must not have more than 2 options.";
                    if (page.Options.Length > 3 && (page.TopLine != null || page.BottomLine != null))
                        return @$"CheckboxPage with a TopLine or BottomLine must not have more than 3 options.";
                    if (page.Options.Length > 4)
                        return @$"CheckboxPage must not have more than 4 options.";
                }
                else if (rawPage.GetType() == typeof(RadioPage))
                {
                    var page = (RadioPage)rawPage;
                    
                    if (page.Options.Length > 2 && page.TopLine != null && page.BottomLine != null)
                        return @$"RadioPage with a TopLine and BottomLine must not have more than 2 options.";
                    if (page.Options.Length > 3 && (page.TopLine != null || page.BottomLine != null))
                        return @$"RadioPage with a TopLine or BottomLine must not have more than 3 options.";
                    if (page.Options.Length > 4)
                        return @$"RadioPage must not have more than 4 options.";
                    
                    if (page.DefaultOption != null && !page.Options.Any(x => x.Name == page.DefaultOption))
                        return @$"No option matching DefaultOption {page.DefaultOption} in RadioPage.";
                }
                else if (rawPage.GetType() == typeof(RadioImagePage))
                {
                    var page = (RadioImagePage)rawPage;
                    
                    if (page.Options.Length > 4)
                        return @$"RadioImagePage must not have more than 4 options.";
                    if (page.DefaultOption != null && !page.Options.Any(x => x.Name == page.DefaultOption))
                        return @$"No option matching DefaultOption {page.DefaultOption} in RadioImagePage.";
                }
            }
            return null;
        }
        
        public static double GetVersionNumber(string toBeParsed)
        {
            // Examples:
            // 0.4
            // 0.4 Alpha
            // 1.0.5
            // 1.0.5 Beta
            
            
            // Remove characters after first space (and the space itself)
            if (toBeParsed.IndexOf(' ') >= 0)
                toBeParsed = toBeParsed.Substring(0, toBeParsed.IndexOf(' '));

            if (toBeParsed.LastIndexOf('.') != toBeParsed.IndexOf('.'))
            {
                // Example: 1.0.5
                toBeParsed = toBeParsed.Remove(toBeParsed.LastIndexOf('.'), 1);
                // Result: 1.05
            }
            
            return double.Parse(toBeParsed, CultureInfo.InvariantCulture);
        }

        public double GetVersionNumber()
        {
            return GetVersionNumber(Version);
        }

        public async Task<string> LatestPlaybookVersion()
        {

            if (!IsValidGit())
            {
                throw new ArgumentException("Link provided is not a proper Git link.");
            }

            string gitPlatform = GetPlaybookGitPlatform();

            string repo = GetRepository();

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("curl/7.55.1"); //Required for GitHub

            string url = gitPlatform switch
            {
                "github.com" => $"https://api.github.com/repos/{repo}/releases",
                "gitlab.com" => $"https://gitlab.com/api/v4/projects/{Uri.EscapeDataString(repo)}/releases",
                _ => $"https://{gitPlatform}/api/v1/repos/{repo}/releases"
            };
            
            var response = await httpClient.GetAsync(url);

            response.EnsureSuccessStatusCode();
                    
            var json = await response.Content.ReadAsStringAsync();
            var array = JArray.Parse(json);

            return (string) array.FirstOrDefault()?["tag_name"];
        }
        public async Task<List<string>> GetPlaybookVersions()
        {

            if (!IsValidGit())
            {
                throw new ArgumentException("Link provided is not a proper Git link.");
            }

            string gitPlatform = GetPlaybookGitPlatform();

            string repo = GetRepository();

            using var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("curl/7.55.1"); //Required for GitHub

            string url = gitPlatform switch
            {
                "github.com" => $"https://api.github.com/repos/{repo}/releases",
                "gitlab.com" => $"https://gitlab.com/api/v4/projects/{Uri.EscapeDataString(repo)}/releases",
                _ => $"https://{gitPlatform}/api/v1/repos/{repo}/releases"
            };
            
            var response = await httpClient.GetAsync(url);

            response.EnsureSuccessStatusCode();
                    
            var json = await response.Content.ReadAsStringAsync();
            var array = JArray.Parse(json);

            var result = new List<string>();
            foreach (var releaseToken in array)
                result.Add((string)releaseToken["tag_name"]);

            return result;
        }
        
        public async Task DownloadLatestPlaybook(BackgroundWorker worker = null)
        {
            string repo = GetRepository();
            string gitPlatform = GetPlaybookGitPlatform();

            var httpClient = new WinUtil.HttpProgressClient();
            httpClient.Client.DefaultRequestHeaders.UserAgent.ParseAdd("curl/7.55.1"); //Required for GitHub

            var downloadUrl = string.Empty;
            var downloadDir = System.IO.Path.Combine(Environment.GetEnvironmentVariable("TEMP"), "AME");
            var downloadPath = System.IO.Path.Combine(downloadDir, "playbook.apbx");

            string baseUrl;
            string releasesUrl;
            string assetsKey;
            string browserDownloadUrlKey;

            switch (gitPlatform)
            {
                case "github.com":
                    baseUrl = "https://api.github.com";
                    releasesUrl = $"{baseUrl}/repos/{repo}/releases";
                    assetsKey = "assets";
                    browserDownloadUrlKey = "browser_download_url";
                    break;

                case "gitlab.com":
                    baseUrl = "https://gitlab.com/api/v4";
                    releasesUrl = $"{baseUrl}/projects/{Uri.EscapeDataString(repo)}/releases";
                    assetsKey = "assets.links";
                    browserDownloadUrlKey = "direct_asset_url";
                    break;

                default:
                    baseUrl = $"https://{gitPlatform}/api/v1";
                    releasesUrl = $"{baseUrl}/repos/{repo}/releases";
                    assetsKey = "assets";
                    browserDownloadUrlKey = "browser_download_url";
                    break;
            }

            var releasesResponse = await httpClient.GetAsync(releasesUrl);
            releasesResponse.EnsureSuccessStatusCode();

            var releasesContent = await releasesResponse.Content.ReadAsStringAsync();
            var releases = JArray.Parse(releasesContent);
            var release = releases.FirstOrDefault();

            long size = 3000000;
            
            if (release?.SelectToken(assetsKey) is JArray assets)
            {
                var asset = assets.FirstOrDefault(a => a["name"].ToString().EndsWith(".apbx"));
                if (asset != null)
                {
                    downloadUrl = asset[browserDownloadUrlKey]?.ToString();
                    
                    if (asset["size"] != null) 
                        long.TryParse(asset["size"].ToString(), out size);
                }
            }

            if (worker != null)
                worker.ReportProgress(10);
            
            // Download the release asset
            if (!string.IsNullOrEmpty(downloadUrl))
            {
                httpClient.Client.DefaultRequestHeaders.Clear();
                
                httpClient.ProgressChanged += (totalFileSize, totalBytesDownloaded, progressPercentage) => {
                    if (progressPercentage.HasValue && worker != null)
                        worker.ReportProgress((int)Math.Ceiling(10 + (progressPercentage.Value * 0.7)));
                };
                
                await httpClient.StartDownload(downloadUrl, downloadPath, size);
            }
            httpClient.Dispose();
        }

        public string GetRepository()
        {
            if (Git == null)
            {
                return null;
            }

            var urlSegments = Git.Replace("https://", "").Replace("http://", "").Split('/');
            return urlSegments[1] +"/"+ urlSegments[2];
        }

        public string GetPlaybookGitPlatform()
        {
            if (this.Git == null)
            {
                throw new NullReferenceException("No Git link available.");
            }

            return new Uri(Git).Host;
        }

        public bool IsValidGit()
        {
            if (Git == null)
            {
                throw new NullReferenceException("No Git link available.");
            }

            return Regex.IsMatch(Git, "((git|ssh|http(s)?)|(git@[\\w\\.]+))(:(//)?)([\\w\\.@\\:/\\-~]+)(/)?");;
        }
        public override string ToString()
        {
            return $"Name: {Name}\nDescription: {Description}\nUsername: {Username}\nDetails: {Details}\nRequirements: {Requirements}."; 
        }
        [XmlType("CheckboxPage")]
        public class CheckboxPage : FeaturePage
        {
            public class CheckboxOption : Option
            {
                [XmlAttribute]
                public bool IsChecked { get; set; } = true;
            }

            [XmlArray]
            [XmlArrayItem(ElementName = "CheckboxOption", Type = typeof(CheckboxOption))]
            public Option[] Options { get; set; }
        }
        public class RadioPage : FeaturePage
        {
            [XmlAttribute]
            public string DefaultOption { get; set; } = null;
            public class RadioOption : Option
            {
            }

            [XmlArray]
            [XmlArrayItem(ElementName = "RadioOption", Type = typeof(RadioOption))]
            public Option[] Options { get; set; }
        }
        public class RadioImagePage : FeaturePage
        {
            [XmlAttribute]
            public string DefaultOption { get; set; } = null;
            public class RadioImageOption : Option
            {
                public string FileName { get; set; } = null;

                public bool Fill { get; set; } = false;
                [XmlAttribute]
                public bool None { get; set; } = false;

                public string GradientTopColor { get; set; } = null;
                public string GradientBottomColor { get; set; } = null;
            }
            
            [XmlArray]
            [XmlArrayItem(ElementName = "RadioImageOption", Type = typeof(RadioImageOption))]
            public Option[] Options { get; set; }

            [XmlAttribute]
            public bool CheckDefaultBrowser { get; set; } = false;
        }
        
        public class FeaturePage
        {
            [XmlAttribute]
            public string DependsOn { get; set; } = null;
            [XmlAttribute]
            public bool IsRequired { get; set; } = false;
            public Line TopLine { get; set; } = null;
            public Line BottomLine { get; set; } = null;
            
            public class Option
            {
                public string Name { get; set; } = null;
                public virtual string Text { get; set; }
                
                [XmlAttribute]
                public string DependsOn { get; set; } = null;
            }
            public class Line
            {
                [XmlAttribute("Text")]
                public string Text { get; set; }
                [XmlAttribute("Link")]
                public string Link { get; set; } = null;
            }
            [XmlAttribute]
            public string Description { get; set; }
        }
    }
}
