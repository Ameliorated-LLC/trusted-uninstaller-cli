using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Xml;
using System.Xml.Serialization;
using Core;
using Core.Actions;
using Core.Exceptions;
using Interprocess;
using JetBrains.Annotations;
using Microsoft.Win32;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Parser;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using RegistryKeyAction = TrustedUninstaller.Shared.Actions.RegistryKeyAction;
using TaskAction = TrustedUninstaller.Shared.Tasks.TaskAction;
using UninstallTaskStatus = TrustedUninstaller.Shared.Tasks.UninstallTaskStatus;

namespace TrustedUninstaller.Shared
{

    public static class AmeliorationUtil
    {

        private static readonly HttpClient Client = new HttpClient();

        public static Playbook Playbook { set; get; } = new Playbook();

        public static bool UseKernelDriver = false;

        public static readonly List<string> ErrorDisplayList = new List<string>();

        public static int GetProgressMaximum(List<ITaskAction> actions) => actions.Sum(action => action.GetProgressWeight());

        private static bool IsApplicable([CanBeNull] Playbook upgradingFrom, bool? onUpgrade, [CanBeNull] string[] onUpgradeVersions, [CanBeNull] string option)
        {
            if (upgradingFrom == null)
                return !onUpgrade.GetValueOrDefault();

            bool isApplicable = true;
            bool? versionApplicable = null;
            if (onUpgradeVersions != null)
            {
                if (onUpgrade == null)
                    throw new YamlException("onUpgrade must be defined when using onUpgradeVersions");

                versionApplicable = 
                    onUpgradeVersions.Where(version => !version.StartsWith("!")).Any(version => IsApplicableUpgrade(upgradingFrom.Version, version))
                    &&
                    onUpgradeVersions.Where(version => version.StartsWith("!")).All(version => IsApplicableUpgrade(upgradingFrom.Version, version));
                isApplicable = versionApplicable.Value;
            }

            if (onUpgrade == null)
                return true;

            if (isApplicable && option != null)
            {
                isApplicable = String.Equals(option.Trim(), "ignore", StringComparison.OrdinalIgnoreCase) ||
                    (!(upgradingFrom.AvailableOptions?.Contains(option) ?? false) || (upgradingFrom.SelectedOptions?.Contains(option) ?? false));
            }
            
            if (upgradingFrom.GetVersionNumber() == Playbook.GetVersionNumber() && (versionApplicable == null || !onUpgradeVersions.Any(x => x.Equals(Playbook.Version))))
                return !onUpgrade.Value && !isApplicable;

            return onUpgrade.Value ? isApplicable : !isApplicable;
        }
        
        [CanBeNull]
        public static List<ITaskAction> ParseActions(string configPath, List<string> options, string file, [CanBeNull] Playbook upgradingFrom)
        {
            var returnExceptionMessage = string.Empty;
            try
            {
                if (!File.Exists(Path.Combine(configPath, file)))
                    return null;
                
                var configData = File.ReadAllText(Path.Combine(configPath, file));
                var task = PlaybookParser.Deserializer.Deserialize<UninstallTask>(configData);

                if ((!IsApplicable(upgradingFrom, task.OnUpgrade, task.OnUpgradeVersions, task.PreviousOption ?? task.Option) || 
                        !IsApplicableOption(task.Option, Playbook.Options) || !IsApplicableArch(task.Arch)) ||
                    (task.Builds != null && (
                        !task.Builds.Where(build => !build.StartsWith("!")).Any(build => IsApplicableWindowsVersion(build))
                        ||
                        task.Builds.Where(build => build.StartsWith("!")).Any(build => !IsApplicableWindowsVersion(build)))) ||
                    (task.Options != null && (
                        !task.Options.Where(option => !option.StartsWith("!")).Any(option => IsApplicableOption(option, Playbook.Options))
                        ||
                        task.Options.Where(option => option.StartsWith("!")).Any(option => !IsApplicableOption(option, Playbook.Options)))))
                {
                    return null;
                }
                
                var list = new List<ITaskAction>();

                // ReSharper disable once PossibleInvalidCastExceptionInForeachLoop
                foreach (Tasks.TaskAction taskAction in task.Actions)
                {
                    if ((!IsApplicable(upgradingFrom, taskAction.OnUpgrade, taskAction.OnUpgradeVersions, taskAction.PreviousOption ?? taskAction.Option) || 
                            !IsApplicableOption(taskAction.Option, options) || !IsApplicableArch(taskAction.Arch)) ||
                        (taskAction.Builds != null && (
                            !taskAction.Builds.Where(build => !build.StartsWith("!")).Any(build => IsApplicableWindowsVersion(build))
                            ||
                            taskAction.Builds.Where(build => build.StartsWith("!")).Any(build => !IsApplicableWindowsVersion(build)))) ||
                        (taskAction.Options != null && (
                            !taskAction.Options.Where(option => !option.StartsWith("!")).Any(option => IsApplicableOption(option, Playbook.Options))
                            ||
                            taskAction.Options.Where(option => option.StartsWith("!")).Any(option => !IsApplicableOption(option, Playbook.Options)))))
                    {
                        continue;
                    }
                    
                    if (taskAction is Actions.TaskAction taskTaskAction)
                    {
                        if (!File.Exists(Path.Combine(configPath, taskTaskAction.Path)))
                            throw new FileNotFoundException("Could not find YAML file: " + taskTaskAction.Path);
                        try
                        {
                            list.AddRange(ParseActions(configPath, options, taskTaskAction.Path, upgradingFrom) ?? new List<ITaskAction>());
                        }
                        catch (Exception e)
                        {
                            if (e is SerializationException exception)
                                returnExceptionMessage += exception.Message + Environment.NewLine + Environment.NewLine;
                            else
                                throw;
                        }
                    }
                    else
                    {
                        list.Add((ITaskAction)taskAction);
                    }
                }

                foreach (var childTask in task.Tasks)
                {
                    if (!File.Exists(Path.Combine(configPath, childTask)))
                        throw new FileNotFoundException("Could not find YAML file: " + childTask);
                    try
                    {
                        list.AddRange(ParseActions(configPath, options, childTask, upgradingFrom) ?? new List<ITaskAction>());
                    }
                    catch (Exception e)
                    {
                        if (e is SerializationException exception)
                            returnExceptionMessage += exception.Message + Environment.NewLine + Environment.NewLine;
                        else
                            throw;
                    }
                }

                if (!string.IsNullOrEmpty(returnExceptionMessage))
                    throw new SerializationException(returnExceptionMessage.TrimEnd('\n', '\r'));

                return list;
            }
            catch (YamlException e)
            {
                var faultyText = Wrap.ExecuteSafe(() => GetFaultyYamlText(Path.Combine(configPath, file), e), true);
                if (faultyText.Failed || string.IsNullOrWhiteSpace(faultyText.Value))
                {
                    Log.EnqueueExceptionSafe(e);
                    throw new SerializationException(e.Message.TrimEnd('.') + $" in {Path.GetFileName(file)}.");
                }
                else
                {
                    Log.EnqueueExceptionSafe(e, ("YAML", faultyText.Value));
                    throw new SerializationException(FilterYAMLMessage(e).TrimEnd('.') + $" in {Path.GetFileName(file)}:{Environment.NewLine}{faultyText.Value}");
                }
            }
        }
        
        public static string GetFaultyYamlText(string yamlFilePath, YamlException yamlEx)
        {
            using (var reader = new StreamReader(yamlFilePath))
            {
                int currentLine = 0;
                StringBuilder sb = new StringBuilder();

                while (!reader.EndOfStream)
                {
                    currentLine++;
                    string line = reader.ReadLine();
                    if (line == null)
                        throw new IndexOutOfRangeException();

                    var prefix = $"Line {currentLine}: ";
                    if (currentLine == yamlEx.Start.Line)
                    {
                        if (yamlEx.Start.Line == yamlEx.End.Line)
                        {
                            int endIndexInLine = yamlEx.End.Column - Math.Max(0, yamlEx.Start.Column - 1);
                            var text = line.Substring(Math.Max(0, yamlEx.Start.Column - 1), endIndexInLine);
                            if (text.Length <= 1 || string.IsNullOrWhiteSpace(text))
                                text = line;

                            text = string.Join(Environment.NewLine + prefix.Length, text.SplitByLength(25).Select(x => x.Trim()));

                            sb.Append(prefix + text);
                            break;
                        }
                        else
                        {
                            var text = line.Substring(Math.Max(0, yamlEx.Start.Column - 1));
                            text = string.Join(Environment.NewLine + prefix.Length, text.SplitByLength(25).Select(x => x.Trim()));
                            sb.Append(prefix + text);
                        }
                    }
                    else if (currentLine > yamlEx.Start.Line && currentLine < yamlEx.End.Line)
                    {
                        var text = string.Join(Environment.NewLine + prefix.Length, line.SplitByLength(25).Select(x => x.Trim()));
                        sb.Append(Environment.NewLine).Append(prefix + text);
                    } else if (currentLine == yamlEx.End.Line)
                    {
                        var text = string.Join(Environment.NewLine + prefix.Length, line.Substring(0, yamlEx.End.Column).SplitByLength(25).Select(x => x.Trim()));
                        sb.Append(Environment.NewLine).Append(prefix + text);
                        break;
                    }
                }

                var faultyText = sb.ToString();
                return faultyText;
            }
        }
        private static string FilterYAMLMessage(YamlException exception)
        {
            int count = 0;
            int i = 0;

            for (; i < exception.Message.Length; i++)
            {
                if (exception.Message[i] == '(')
                    ++count;
                else if (exception.Message[i] == ')')
                    --count;

                if (exception.Message.Length >= i + 1 + 3 && exception.Message.Substring(i + 1, 3) == " - ")
                {
                    i += 3;
                    continue;
                }
                if (count == 0)
                    return exception.Message.Substring(i + 1).Trim().TrimStart(':', ' ');
            }
            throw new UnexpectedException();
        }

        public static async Task<bool> DoActions(List<ITaskAction> actions, string logFolder, Action<int> progressReport)
        {
            bool errorOccurred = false;
            foreach (ITaskAction action in actions)
            {
                var actionName = action.GetType().ToString().Split('.').Last();
                using var writer = new Output.OutputWriter(actionName.Replace("Action", ""), Path.Combine(logFolder, "Output.txt"), Path.Combine(logFolder, "Log.yml"));
                writer.LogOptions.SourceOverride = actionName;

                ErrorAction errorAction = ((Tasks.TaskAction)action).ErrorAction ?? action.GetDefaultErrorAction();
                var errorString = action.ErrorString();
                var retryAllowed = ((Tasks.TaskAction)action).AllowRetries ?? action.GetRetryAllowed();
                
                int i = 0;
                try
                {
                    do
                    {
                        if (i > 0)
                            writer.WriteLineSafe("Warning", "Action detected as unsuccessful. Retrying...");
                        try
                        {
                            var actionTask = action.RunTask(writer);
                            if (actionTask == null)
                                action.RunTaskOnMainThread(writer);
                            else await actionTask;
                            action.ResetProgress();
                        }
                        catch (Exception e)
                        {
                            action.ResetProgress();

                            if (e is ErrorHandlingException errorHandlingException)
                            {
                                if (errorHandlingException.Action == TaskAction.ExitCodeAction.Retry || errorHandlingException.Action == TaskAction.ExitCodeAction.RetryError)
                                {
                                    errorString = errorHandlingException.Message;
                                    Thread.Sleep(50);
                                    i += 2;
                                    if (i == 10)
                                    {
                                        if (errorHandlingException.Action == TaskAction.ExitCodeAction.Retry)
                                        {
                                            i = 0;
                                            break;
                                        }
                                        if (errorHandlingException.Action == TaskAction.ExitCodeAction.RetryError)
                                        {
                                            i = 0;
                                            Log.WriteExceptionSafe(e, errorHandlingException.Message, new Log.LogOptions(writer));
                                            errorOccurred = true;
                                            break;
                                        }
                                    }
                                    continue;
                                }
                                errorAction = errorHandlingException.Action switch
                                {
                                    TaskAction.ExitCodeAction.Log => ErrorAction.Log,
                                    TaskAction.ExitCodeAction.Error => ErrorAction.Notify,
                                    TaskAction.ExitCodeAction.Halt => ErrorAction.Halt,
                                    _ => ErrorAction.Log
                                };

                                errorString = errorHandlingException.Message;
                                ((Tasks.TaskAction)action).IgnoreErrors = false;
                                i = 10;
                                break;
                            }

                            Log.WriteExceptionSafe(e, null, new Log.LogOptions(writer));
                            
                            List<string> ExceptionBreakList = new List<string>() { "System.ArgumentException", "System.SecurityException", "System.UnauthorizedAccessException", "System.TimeoutException" };
                            if (ExceptionBreakList.Any(x => x.Equals(e.GetType().ToString())) || !retryAllowed)
                            {
                                i = 10;
                                break;
                            }
                            Thread.Sleep(300);
                        }

                        if (i > 0) Thread.Sleep(50);
                        i++;
                        
                        if (action.GetStatus(writer) == UninstallTaskStatus.Completed)
                            break;
                    } while (i < 10);
                }
                catch (Exception e)
                {
                    if (!((Tasks.TaskAction)action).IgnoreErrors)
                    {
                        if (errorAction == ErrorAction.Log)
                            Log.WriteExceptionSafe(LogType.Info, e, "An ignored error occurred while running an action.", new Log.LogOptions(writer));
                        if (errorAction == ErrorAction.Notify)
                        {
                            Log.WriteExceptionSafe(e, "An error occurred while running an action.", new Log.LogOptions(writer));
                            errorOccurred = true;
                        }
                        if (errorAction == ErrorAction.Halt)
                        {
                            Log.WriteExceptionSafe(LogType.Critical, e, "Playbook halted due to a failed critical action.", new Log.LogOptions(writer));
                            throw e;
                        }
                    }
                }
                
                progressReport(action.GetProgressWeight());
                if (i == 10)
                {
                    if (!((Tasks.TaskAction)action).IgnoreErrors)
                    {
                        if (errorAction == ErrorAction.Log)
                            Log.WriteSafe(LogType.Info, errorString, null, new Log.LogOptions(writer));
                        if (errorAction == ErrorAction.Notify)
                        {
                            Log.WriteSafe(LogType.Error, errorString, null, new Log.LogOptions(writer));
                            errorOccurred = true;
                        }
                        if (errorAction == ErrorAction.Halt)
                        {
                            Log.WriteSafe(LogType.Critical, "Playbook halted due to a critical error: " + errorString, null, new Log.LogOptions(writer));
                            throw new Exception("Critical error: " + errorString);
                        }
                    }
                }
            }

            ProcessPrivilege.ResetTokens();
            return errorOccurred;
        }

        public static Playbook DeserializePlaybook(string dir)
        {
            Playbook pb;
            
            XmlSerializer serializer = new XmlSerializer(typeof(Playbook));
            /*serializer.UnknownElement += delegate(object sender, XmlElementEventArgs args)
            {
                MessageBox.Show(args.Element.Name);
            };
            serializer.UnknownAttribute += delegate(object sender, XmlAttributeEventArgs args)
            {
                MessageBox.Show(args.Attr.Name);
            };*/
            try
            {
                using (XmlReader reader = XmlReader.Create($"{dir}\\playbook.conf"))
                {
                    pb = (Playbook)serializer.Deserialize(reader);
                }
            }
            catch (InvalidOperationException e)
            {
                if (e.InnerException == null)
                    throw;

                throw new XmlException(e.Message.TrimEnd('.') + ": " + e.InnerException.Message);
            }

            pb.Path = dir;
            return pb;
        }

        [Serializable]
        public class PlaybookMetadata : Log.ILogMetadata
        {
            public PlaybookMetadata(string[] options) => Options = options;
         
            public DateTime CreationTime { get; set; }
            public string ClientVersion { get; set; }
            public string WindowsVersion { get; set; }
            public string UserLanguage { get; set; }
            public Architecture Architecture { get; set; }
            public string SystemMemory { get; set; }
            public int SystemThreads { get; set; }
            public string[] Options { get; set; }
            public virtual void Construct()
            {
                ClientVersion = Globals.CurrentVersion;
                WindowsVersion = $"Windows {Win32.SystemInfoEx.WindowsVersion.MajorVersion} {Win32.SystemInfoEx.WindowsVersion.Edition} {Win32.SystemInfoEx.WindowsVersion.BuildNumber}.{Win32.SystemInfoEx.WindowsVersion.UpdateNumber}";
                UserLanguage = CultureInfo.InstalledUICulture.ToString();
                SystemMemory = StringUtils.HumanReadableBytes(Win32.SystemInfoEx.GetSystemMemoryInBytes());
                SystemThreads = Environment.ProcessorCount;
                Architecture = Win32.SystemInfoEx.SystemArchitecture;
                CreationTime = DateTime.UtcNow;
            }

            public string Serialize(ISerializer serializer) => serializer.Serialize(this);
        }
        
        [InterprocessMethod(Level.TrustedInstaller)]
        public static async Task<bool> RunPlaybook(string playbookPath, string[] options, string logFolder, InterLink.InterProgress progress, [CanBeNull] InterLink.InterMessageReporter statusReporter, bool useKernelDriver)
        {
            Log.LogFileOverride = Path.Combine(logFolder, "Log.yml");
            Log.MetadataSource = new PlaybookMetadata(options);

            AmeliorationUtil.UseKernelDriver = useKernelDriver;

            AmeliorationUtil.Playbook = AmeliorationUtil.DeserializePlaybook(playbookPath);
            AmeliorationUtil.Playbook.Options = options?.ToList();

            Playbook[] appliedPlaybooks = Playbook.GetAppliedPlaybooks();
            Playbook upgradingFrom = Playbook.LastAppliedMatch(appliedPlaybooks);
            if (upgradingFrom != null && (!Playbook.IsUpgradeApplicable(upgradingFrom.Version) && !(upgradingFrom.GetVersionNumber() <= Playbook.GetVersionNumber())))
                upgradingFrom = null;
            
            List<ITaskAction> actions = ParseActions($"{Playbook.Path}\\Configuration", AmeliorationUtil.Playbook.Options, File.Exists($"{Playbook.Path}\\Configuration\\main.yml")  ? "main.yml" :  "custom.yml", upgradingFrom);
            if (actions == null)
                throw new SerializationException("No applicable tasks were found in the Playbook.");
            
            if (UseKernelDriver)
            {
                //Check if KPH is installed.
                ServiceController service = ServiceController.GetDevices()
                    .FirstOrDefault(s => s.DisplayName == "KProcessHacker2");
                if (service == null)
                {
                    //Installs KPH
                    await WinUtil.RemoveProtectionAsync();
                }
            }

            var totalProgress = Math.Max(AmeliorationUtil.GetProgressMaximum(actions), 1);
            var progressLeft = totalProgress;
            Action<int> progressReport = addition =>
            {
                progressLeft -= addition;
                var progressValue = 1 - ((decimal)progressLeft / totalProgress);
                progress.Report(progressValue * 100);
            };

            WriteStatusAction.StatusReporter = statusReporter;

            bool errorOccurred = await DoActions(actions, logFolder, progressReport);

            WinUtil.RegistryManager.UnhookUserHives();

            //Check if the kernel driver is installed.
            //service = ServiceController.GetDevices()
                //.FirstOrDefault(s => s.DisplayName == "KProcessHacker2");
            if (UseKernelDriver)
            { 
                //Remove Process Hacker's kernel driver.
                await WinUtil.UninstallDriver();
                
                CoreActions.SafeRun(new Core.Actions.RegistryKeyAction()
                {
                    KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\KProcessHacker2",
                });
            }

            return errorOccurred;
        }
        public static async Task DownloadLanguagesAsync(IEnumerable<string> langsSelected)
        {

            foreach (var lang in langsSelected)
            {

                var lowerLang = lang.ToLower();

                var arch = RuntimeInformation.OSArchitecture;
                var winVersion = Environment.OSVersion.Version.Build;

                var convertedArch = "";
                switch (arch)
                {
                    case Architecture.X64:
                        convertedArch = "amd64";
                        break;
                    case Architecture.Arm64:
                        convertedArch = "arm64";
                        break;
                    case Architecture.X86:
                        convertedArch = "x86";
                        break;
                }

                var uuidOfWindowsVersion = "";
                var uuidResponse =
                    await Client.GetAsync(
                        $"https://api.uupdump.net/listid.php?search={winVersion}%20{convertedArch}&sortByDate=1");
                switch (uuidResponse.StatusCode)
                {
                    //200 Status code
                    case HttpStatusCode.OK:
                        {
                            var result = uuidResponse.Content.ReadAsStringAsync().Result;
                            //Gets the UUID of the first build object in the response, we take the first since it's the newest.
                            uuidOfWindowsVersion = (string)(JToken.Parse(result)["response"]?["builds"]?.Children().First()
                                .Children().First().Last());
                            break;
                        }
                    //400 Status code
                    case HttpStatusCode.BadRequest:
                        {
                            var result = uuidResponse.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Bad request.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    //429 Status code
                    case (HttpStatusCode)429:
                        {
                            var result = uuidResponse.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Too many requests, try again later.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    //500 Status code
                    case HttpStatusCode.InternalServerError:
                        {
                            var result = uuidResponse.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Internal Server Error.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                var responseString =
                    await Client.GetAsync(
                        $"https://api.uupdump.net/get.php?id={uuidOfWindowsVersion}&lang={lowerLang}");
                switch (responseString.StatusCode)
                {
                    //200 Status code
                    case HttpStatusCode.OK:
                        {

                            var result = responseString.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            //Add different urls to different packages to a list
                            var urls = new Dictionary<string, string>
                        {
                            {
                                "basic", (string) data["response"]["files"][
                                    $"microsoft-windows-languagefeatures-basic-{lowerLang}-package-{convertedArch}.cab"]
                                [
                                    "url"]
                            },
                            {
                                "hw", (string) data["response"]["files"][
                                    $"microsoft-windows-languagefeatures-handwriting-{lowerLang}-package-{convertedArch}.cab"]
                                [
                                    "url"]
                            },
                            {
                                "ocr", (string) data["response"]["files"][
                                    $"microsoft-windows-languagefeatures-ocr-{lowerLang}-package-{convertedArch}.cab"][
                                    "url"]
                            },
                            {
                                "speech", (string) data["response"]["files"][
                                    $"microsoft-windows-languagefeatures-speech-{lowerLang}-package-{convertedArch}.cab"]
                                [
                                    "url"]
                            },
                            {
                                "tts", (string) data["response"]["files"][
                                    $"microsoft-windows-languagefeatures-texttospeech-{lowerLang}-package-{convertedArch}.cab"]
                                [
                                    "url"]
                            }
                        };


                            var amePath = Path.Combine(Path.GetTempPath(), "AME\\");
                            //Create the directory if it doesn't exist.
                            var file = new FileInfo(amePath);
                            file.Directory?.Create(); //Does nothing if the directory already exists

                            //Final result being "temp\AME\Languages\file.cab"
                            var downloadPath = Path.Combine(amePath, "Languages\\");
                            file = new FileInfo(downloadPath);
                            file.Directory?.Create();
                            using (var webClient = new WebClient())
                            {
                                Console.WriteLine($"Downloading {lowerLang}.cab file, please wait..");
                                foreach (var url in urls)
                                {
                                    //Check if the file exists, if it does exist, skip it.
                                    if (File.Exists(Path.Combine(downloadPath, $"{url.Key}_{lowerLang}.cab")))
                                    {
                                        Console.WriteLine($"{url.Key}_{lowerLang} already exists, skipping.");
                                        continue;
                                    }
                                    //Output file format: featureName_languageCode.cab: speech_de-de.cab
                                    webClient.DownloadFile(url.Value, $@"{downloadPath}\{url.Key}_{lowerLang}.cab");
                                }
                            }

                            break;
                        }
                    //400 Status code
                    case HttpStatusCode.BadRequest:
                        {
                            var result = responseString.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Bad request.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    //429 Status code
                    case (HttpStatusCode)429:
                        {
                            var result = responseString.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Too many requests, try again later.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    //500 Status code
                    case HttpStatusCode.InternalServerError:
                        {
                            var result = responseString.Content.ReadAsStringAsync().Result;
                            dynamic data = JObject.Parse(result);
                            Console.WriteLine($"Internal Server Error.\r\nError:{data["response"]["error"]}");
                            break;
                        }
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        private static bool IsApplicableUpgrade(string oldVersion, string allowedVersion)
        {
            var oldVersionNumber = Playbook.GetVersionNumber(oldVersion);
            var version = allowedVersion;
            bool negative = false;
            if (version.StartsWith("!"))
            {
                version = version.TrimStart('!');
                negative = true;
            }
            bool result = false;

            if (version.StartsWith(">="))
            {
                var parsed = Playbook.GetVersionNumber(version.Substring(2));
                if (oldVersionNumber >= parsed)
                    result = true;
            }
            else if (version.StartsWith("<="))
            {
                var parsed = Playbook.GetVersionNumber(version.Substring(2));
                if (oldVersionNumber <= parsed)
                    result = true;
            }
            else if (version.StartsWith(">"))
            {
                var parsed = Playbook.GetVersionNumber(version.Substring(1));
                if (oldVersionNumber > parsed)
                    result = true;
            }
            else if (version.StartsWith("<"))
            {
                var parsed = Playbook.GetVersionNumber(version.Substring(1));
                if (oldVersionNumber < parsed)
                    result = true;
            }
            else
            {
                var parsed = Playbook.GetVersionNumber(version);
                if (oldVersionNumber == parsed)
                    result = true;
            }

            return negative ? !result : result;
        }
        
        private static bool IsApplicableWindowsVersion(string version)
        {
            bool negative = false;
            if (version.StartsWith("!"))
            {
                version = version.TrimStart('!');
                negative = true;
            }
            bool result = false;

            bool compareUpdateBuild = version.Contains(".");
            var currentBuild = decimal.Parse(compareUpdateBuild ? Win32.SystemInfoEx.WindowsVersion.BuildNumber + "." + Win32.SystemInfoEx.WindowsVersion.UpdateNumber : Win32.SystemInfoEx.WindowsVersion.BuildNumber.ToString(), CultureInfo.InvariantCulture);

            if (version.StartsWith(">="))
            {
                var parsed = decimal.Parse(version.Substring(2), CultureInfo.InvariantCulture);
                if (currentBuild >= parsed)
                    result = true;
            }
            else if (version.StartsWith("<="))
            {
                var parsed = decimal.Parse(version.Substring(2), CultureInfo.InvariantCulture);
                if (currentBuild <= parsed)
                    result = true;
            }
            else if (version.StartsWith(">"))
            {
                var parsed = decimal.Parse(version.Substring(1), CultureInfo.InvariantCulture);
                if (currentBuild > parsed)
                    result = true;
            }
            else if (version.StartsWith("<"))
            {
                var parsed = decimal.Parse(version.Substring(1), CultureInfo.InvariantCulture);
                if (currentBuild < parsed)
                    result = true;
            }
            else
            {
                var parsed = decimal.Parse(version, CultureInfo.InvariantCulture);
                if (currentBuild == parsed)
                    result = true;
            }

            return negative ? !result : result;
        }
        
        private static bool IsApplicableOption(string option, List<string> options)
        {
            if (String.IsNullOrEmpty(option))
                return true;

            if (option.Contains("&"))
            {
                if (option.Contains("!"))
                    throw new ArgumentException("YAML options item must not contain both & and !", "options");

                return option.Split('&').All(splitOption => IsApplicableOption(splitOption, options));
            }
            
            bool negative = false;
            if (option.StartsWith("!"))
            {
                option = option.TrimStart('!');
                negative = true;
            }
            
            if (options == null)
                return negative ? true : false;

            var result = options.Contains(option, StringComparer.OrdinalIgnoreCase);

            return negative ? !result : result;
        }
        
        private static bool IsApplicableArch(string arch)
        {
            if (String.IsNullOrEmpty(arch))
                return true;
            
            bool negative = false;
            if (arch.StartsWith("!"))
            {
                arch = arch.TrimStart('!');
                negative = true;
            }

            var result = String.Equals(arch, Win32.SystemInfoEx.SystemArchitecture.ToString(), StringComparison.OrdinalIgnoreCase);

            return negative ? !result : result;
        }
    }
}
