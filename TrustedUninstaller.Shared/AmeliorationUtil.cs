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
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Xml;
using System.Xml.Serialization;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Parser;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.Shared
{

    public static class AmeliorationUtil
    {
        private static readonly ConfigParser Parser = new ConfigParser();

        private static readonly HttpClient Client = new HttpClient();

        public static Playbook Playbook { set; get; } = new Playbook();

        public static bool UseKernelDriver = false;

        public static readonly List<string> ErrorDisplayList = new List<string>();

        public static int GetProgressMaximum(List<string> options)
        {
            return Parser.Tasks.Sum(task => task.Actions.Sum(action =>
            {
                var taskAction = (TaskAction)action;
                if ((!IsApplicableOption(taskAction.Option, options) || !IsApplicableArch(taskAction.Arch)) ||
                    (taskAction.Builds != null && (
                        !taskAction.Builds.Where(build => !build.StartsWith("!")).Any(build => IsApplicableWindowsVersion(build))
                        ||
                        taskAction.Builds.Where(build => build.StartsWith("!")).Any(build => !IsApplicableWindowsVersion(build)))) ||
                    (taskAction.Options != null && (
                        !taskAction.Options.Where(option => !option.StartsWith("!")).Any(option => IsApplicableOption(option, Playbook.Options))
                        ||
                        taskAction.Options.Where(option => option.StartsWith("!")).Any(option => !IsApplicableOption(option, Playbook.Options)))))
                {
                    return 0;
                }

                return action.GetProgressWeight();
            }));
        }
        
        public static bool AddTasks(string configPath, string file)
        {
            try
            {
                //This allows for a proper detection of if any error occurred, and if so the CLI will relay an :AME-Fatal Error:
                //This is important, as we want the process to stop immediately if a YAML syntax error was detected.
                bool hadError = false;
                
                //Adds the config file to the parser's task list
                Parser.Add(Path.Combine(configPath, file));

                var currentTask = Parser.Tasks[Parser.Tasks.Count - 1];

                if ((!IsApplicableOption(currentTask.Option, Playbook.Options) || !IsApplicableArch(currentTask.Arch)) ||
                    (currentTask.Builds != null && (
                        !currentTask.Builds.Where(build => !build.StartsWith("!")).Any(build => IsApplicableWindowsVersion(build))
                        ||
                        currentTask.Builds.Where(build => build.StartsWith("!")).Any(build => !IsApplicableWindowsVersion(build)))) ||
                    (currentTask.Options != null && (
                        !currentTask.Options.Where(option => !option.StartsWith("!")).Any(option => IsApplicableOption(option, Playbook.Options))
                        ||
                        currentTask.Options.Where(option => option.StartsWith("!")).Any(option => !IsApplicableOption(option, Playbook.Options)))))
                {
                    Parser.Tasks.Remove(currentTask);
                    return true;
                }
                    

                //Get the features of the last added task (the task that was just added from the config file)
                var features = currentTask.Features;
                
                //Each feature would reference a directory that has a YAML file, we take those directories and then run the
                //AddTasks function again, until we reach a file that doesn't reference any other YAML files, and add them
                //all to the parser's tasks list.
                if (features == null) return true;
                foreach (var feature in features)
                {
                    var subResult = AddTasks(configPath, feature);
                    
                    // We could return false here, however we want to output ALL detected YAML errors,
                    // which is why we continue here.
                    if (!subResult) hadError = true;
                }

                return hadError ? false : true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error adding tasks in {configPath + "\\" + file}:\r\n{e.Message}");
                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, $"Error adding tasks in {configPath + "\\" + file}.");
                return false;
            }
        }
        public static async Task<int> DoActions(UninstallTask task, UninstallTaskPrivilege privilege)
        {
            try
            {
                //If the privilege is admin and the program is running as TI, do not do the action.
                //if (privilege == UninstallTaskPrivilege.Admin && WinUtil.IsTrustedInstaller())
                //{
                //    return 0;
                //}
                
                if (!WinUtil.IsTrustedInstaller())
                {
                    Console.WriteLine("Relaunching as Trusted Installer!");
                    
                    var mmf = MemoryMappedFile.CreateNew("ImgA", 30000000);
                    WinUtil.RelaunchAsTrustedInstaller();
                    if (NativeProcess.Process == null)
                    {
                        ErrorLogger.WriteToErrorLog($"Could not launch TrustedInstaller process. Return output was null.",
                            Environment.StackTrace, "Error while attempting to sync with TrustedInstaller process.");
                        
                        Console.WriteLine(":AME-Fatal Error: Could not launch TrustedInstaller process.");
                        Environment.Exit(-1);
                    }
                    
                    var delay = 20;
                    while (!NativeProcess.Process.HasExited)
                    {
                        if (delay > 3500)
                        {
                            NativeProcess.Process.Kill();
                            
                            ErrorLogger.WriteToErrorLog($"Could not initialize memory data exchange. Timeframe exceeded.",
                                Environment.StackTrace, "Error while attempting to sync with TrustedInstaller process.");
                            
                            Console.WriteLine(":AME-Fatal Error: Could not initialize memory data exchange.");
                            Environment.Exit(-1);
                        }

                        Task.Delay(delay).Wait();
                        // Kind of inefficient looping this, however it's likely to cause access errors otherwise
                        using var stream = mmf.CreateViewStream();
                        using BinaryReader binReader = new BinaryReader(stream);
                        {
                            var res = binReader.ReadBytes((int)stream.Length);
                            var data = Encoding.UTF8.GetString(res);

                            var end = data.IndexOf('\0');
                            if (end == 0)
                            {
                                delay += 200;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                    
                    var offset = 0;
                    var read = false;
                    using (var stream = mmf.CreateViewStream())
                    {
                        while (!NativeProcess.Process.HasExited || read)
                        {
                            read = false;
                            
                            BinaryReader binReader = new BinaryReader(stream);

                            binReader.BaseStream.Seek(offset, SeekOrigin.Begin);

                            var res = binReader.ReadBytes((int)stream.Length - offset);
                            var data = Encoding.UTF8.GetString(res);

                            var end = data.IndexOf("\0");

                            var content = data.Substring(0, end);
                            offset += Encoding.UTF8.GetBytes(content).Length;

                            var output = content.Split(new [] {Environment.NewLine}, StringSplitOptions.None);
                            if (output.Length > 0) output = output.Take(output.Length - 1).ToArray();
                            
                            foreach (var line in output)
                            {
                                Console.WriteLine(line);
                                read = true;
                                // Introducing ANY delay here makes it lag behind, which isn't ideal
                                //Task.Delay(5).Wait();
                            }
                            Task.Delay(20).Wait();
                        }
                    }
                    mmf.Dispose();
                    return 0; //Only returns after TI is done
                }

                //Goes through the list of tasks that are inside the parser class,
                //and runs the task using the RunTask method
                //Check the Actions folder inside the Shared folder for reference.
                foreach (ITaskAction action in task.Actions)
                {
                    var taskAction = (TaskAction)action;

                    if ((!IsApplicableOption(taskAction.Option, Playbook.Options) || !IsApplicableArch(taskAction.Arch)) ||
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
                    
                    int i = 0;

                    //var actionType = action.GetType().ToString().Replace("TrustedUninstaller.Shared.Actions.", "");

                    try
                    {
                        do
                        {
                            //Console.WriteLine($"Running {actionType}");
                            Console.WriteLine();
                            try
                            {
                                var actionTask = action.RunTask();
                                if (actionTask == null)
                                    action.RunTaskOnMainThread();
                                else await actionTask;
                                action.ResetProgress();
                            }
                            catch (Exception e)
                            {
                                action.ResetProgress();
                                if (e.InnerException != null)
                                {
                                    ErrorLogger.WriteToErrorLog(e.InnerException.Message, e.InnerException.StackTrace, e.Message);
                                }
                                else
                                {
                                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, action.ErrorString());
                                    List<string> ExceptionBreakList = new List<string>() { "System.ArgumentException", "System.SecurityException", "System.UnauthorizedAccessException", "System.TimeoutException" };
                                    if (ExceptionBreakList.Any(x => x.Equals(e.GetType().ToString())))
                                    {
                                        i = 10;
                                        break;
                                    } 
                                }
                                Thread.Sleep(300);
                            }
                            Console.WriteLine($"Status: {action.GetStatus()}");
                            if (i > 0) Thread.Sleep(50);
                            i++;
                        } while (action.GetStatus() != UninstallTaskStatus.Completed && i < 10);
                    }
                    catch (Exception e)
                    {
                        ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, "Critical error while running action.");
                        if (!((TaskAction)action).IgnoreErrors)
                            Console.WriteLine($":AME-ERROR: Critical error while running action: " + e.Message);
                    }

                    if (i == 10)
                    {
                        var errorString = action.ErrorString();
                        ErrorLogger.WriteToErrorLog(errorString, Environment.StackTrace, "Action failed to complete.");
                        // AmeliorationUtil.ErrorDisplayList.Add(errorString) would NOT work here since this
                        // might be a separate process, and thus has to be forwarded via the console
                        if (!((TaskAction)action).IgnoreErrors)
                            Console.WriteLine($":AME-ERROR: {errorString}");
                        //Environment.Exit(-2);
                        Console.WriteLine($"Action completed. Weight:{action.GetProgressWeight()}");
                        continue;
                    }
                    Console.WriteLine($"Action completed. Weight:{action.GetProgressWeight()}");
                }
                Console.WriteLine("Task completed.");
                
                ProcessPrivilege.ResetTokens();
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace,
                    "Encountered an error while doing task actions.");
            }

            return 0;
        }

        public static Task<Playbook> DeserializePlaybook(string dir)
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
            using (XmlReader reader = XmlReader.Create($"{dir}\\playbook.conf"))
            {
                pb = (Playbook)serializer.Deserialize(reader);
            }
            var validateResult = pb.Validate();
            if (validateResult != null)
                throw new XmlException(validateResult);

            if (File.Exists($"{dir}\\options.txt"))
            {
                pb.Options = new List<string>();
                using (var reader = new StreamReader($"{dir}\\options.txt"))
                {
                    while (!reader.EndOfStream)
                        pb.Options.Add(reader.ReadLine());
                }
            }
            pb.Path = dir;
            return Task.FromResult(pb);
        }

        public static async Task<int> StartAmelioration()
        {
            //Needed after defender removal's reboot, the "current directory" will be set to System32
            //After the auto start up.
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            if (Directory.Exists("Logs") && !WinUtil.IsTrustedInstaller())
            {
                if (File.Exists("Logs\\AdminOutput.txt"))
                {
                    File.Delete("Logs\\AdminOutput.txt");
                }

                if (File.Exists("Logs\\TIOutput.txt"))
                {
                    File.Delete("Logs\\TIOutput.txt");
                }
            }

            //Check if KPH is installed.
            ServiceController service = ServiceController.GetDevices()
                                            .FirstOrDefault(s => s.DisplayName == "KProcessHacker2");
            if (service == null)
            {
                //Installs KPH
                await WinUtil.RemoveProtectionAsync();
            }

            var langsFile = Path.Combine($"{Playbook.Path}\\Configuration", "langs.txt");
            //Download language packs that were selected by the user
            if (!File.Exists(langsFile))
            {
                File.Create(langsFile);
            }

            //var langsSelected = File.ReadLines(langsFile);

            //await DownloadLanguagesAsync(langsSelected);

            //Start adding tasks from the top level configuration folder.
            if (!AddTasks($"{Playbook.Path}\\Configuration", "custom.yml"))
            {
                Console.WriteLine($":AME-Fatal Error: Error adding tasks.");
                Environment.Exit(1);
            }

            if (!Parser.Tasks.Any())
            {
                Console.Error.WriteLine($"Couldn't find any tasks.");
                return -1;
            }

            //Sort the list based on the priority value.
            if (Parser.Tasks.Any(x => x.Priority != Parser.Tasks.First().Priority))
                Parser.Tasks.Sort(new TaskComparer());

            bool launched = false;
            foreach (var task in Parser.Tasks.Where(task => task.Actions.Count != 0))
            {
                try
                {
                    //if (prevPriv == UninstallTaskPrivilege.TrustedInstaller && task.Privilege == UninstallTaskPrivilege.TrustedInstaller && !WinUtil.IsTrustedInstaller())
                    if (!WinUtil.IsTrustedInstaller() && launched)
                    {
                        continue;
                    }
                    launched = true;
                    await DoActions(task, task.Privilege);
                    //prevPriv = task.Privilege;
                }
                catch (Exception ex)
                {
                    ErrorLogger.WriteToErrorLog(ex.Message, ex.StackTrace, "Error during DoAction loop.");
                }
            }

            if (WinUtil.IsTrustedInstaller()) return 0;
            
            WinUtil.RegistryManager.UnhookUserHives();

            //Check if the kernel driver is installed.
            //service = ServiceController.GetDevices()
                //.FirstOrDefault(s => s.DisplayName == "KProcessHacker2");
            if (UseKernelDriver)
            { 
                //Remove Process Hacker's kernel driver.
                await WinUtil.UninstallDriver();
                
                await AmeliorationUtil.SafeRunAction(new RegistryKeyAction()
                {
                    KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\KProcessHacker2",
                });
            }
            
            Console.WriteLine();
            Console.WriteLine("Playbook finished.");
            
            return 0;
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

        private static bool IsApplicableWindowsVersion(string version)
        {
            bool negative = false;
            if (version.StartsWith("!"))
            {
                version = version.TrimStart('!');
                negative = true;
            }

            bool compareUpdateBuild = version.Contains(".");
            var currentBuild = decimal.Parse(compareUpdateBuild ? Globals.WinVer + "." + Globals.WinUpdateVer : Globals.WinVer.ToString());

            bool result = false;
            if (version.StartsWith(">="))
            {
                var parsed = decimal.Parse(version.Substring(2));
                if (currentBuild >= parsed)
                    result = true;
            } else if (version.StartsWith("<="))
            {
                var parsed = decimal.Parse(version.Substring(2));
                if (currentBuild <= parsed)
                    result = true;
            } else if (version.StartsWith(">"))
            {
                var parsed = decimal.Parse(version.Substring(1));
                if (currentBuild > parsed)
                    result = true;
            } else if (version.StartsWith("<"))
            {
                var parsed = decimal.Parse(version.Substring(1));
                if (currentBuild < parsed)
                    result = true;
            }
            else
            {
                var parsed = decimal.Parse(version);
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

            var result = String.Equals(arch, RuntimeInformation.ProcessArchitecture.ToString(), StringComparison.OrdinalIgnoreCase);

            return negative ? !result : result;
        }
        
        public static async Task<bool> SafeRunAction(ITaskAction action)
        {
            try
            {
                return await action.RunTask();
            }
            catch (Exception e)
            {
                action.ResetProgress();
                if (e.InnerException != null)
                {
                    ErrorLogger.WriteToErrorLog(e.InnerException.Message, e.InnerException.StackTrace, e.Message);
                }
                else
                {
                    ErrorLogger.WriteToErrorLog(e.Message, e.StackTrace, action.ErrorString());
                }
            }
            return false;
        }
    }
}
