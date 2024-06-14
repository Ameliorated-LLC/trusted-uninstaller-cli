using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Core;
using Interprocess;
using Microsoft.Win32;
using TrustedUninstaller.Shared;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.CLI
{
    public class CLI
    {
        private static async Task ParseArguments(string[] args)
        {
            CommandLine.IArgumentData argumentsData = null;
            try
            {
                argumentsData = CommandLine.ParseArguments(args);
            }
            catch (Exception exception)
            {
                Console.WriteLine("Command line error: " + exception.Message);
                Environment.Exit(1);
            }
            if (argumentsData is CommandLine.Interprocess interprocessData)
            {
                if (interprocessData.Level != Level.Disposable && !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new SecurityException("Process must be run as an administrator.");
                
                Directory.SetCurrentDirectory(Path.GetDirectoryName(Win32.ProcessEx.GetCurrentProcessFileLocation())!);
                await InterLink.InitializeConnection(interprocessData.Level, interprocessData.Mode, interprocessData.Host, interprocessData.Nodes?.Select(x => (Level: x.Level, ProcessID: x.ProcessID)).ToArray() ?? null);
                Environment.Exit(376);
            }
        }
        
        private static async System.Threading.Tasks.Task<int> Main(string[] args)
        {
            if (args.Length > 1 && args[1] == "Interprocess")
                await ParseArguments(args.Skip(1).ToArray());
            
            //Needed after defender removal's reboot, the "current directory" will be set to System32
            //After the auto start up.
            Directory.SetCurrentDirectory(Path.GetDirectoryName(Win32.ProcessEx.GetCurrentProcessFileLocation())!);

            if (!WinUtil.IsAdministrator())
            {
                System.Console.Error.WriteLine("This program must be launched as an Administrator!");
                return -1;
            }
#if !DEBUG
            /*
            if (!WinUtil.IsGenuineWindows())
            {
                System.Console.Error.WriteLine("This program only works on genuine Windows copies!");
                return -1;
            }
            */
#endif

            if (args.Length < 1 || !Directory.Exists(args[0]))
            {
                Console.WriteLine("No Playbook selected.");
                return -1;
            }

            AmeliorationUtil.Playbook = AmeliorationUtil.DeserializePlaybook(Path.GetFullPath(args[0]));

            if (!Directory.Exists($"{AmeliorationUtil.Playbook.Path}\\Configuration") ||
                Directory.GetFiles($"{AmeliorationUtil.Playbook.Path}\\Configuration").Length == 0)
            {
                Console.WriteLine("Configuration folder is empty, put YAML files in it and restart the application.");
                Console.WriteLine($"Current directory: {Directory.GetCurrentDirectory()}");
                return -1;
            }

            ExtractResourceFolder("resources", Directory.GetCurrentDirectory());

            await InterLink.InitializeConnection(Level.Administrator, Mode.TwoWay);
            

            if (!WinUtil.IsTrustedInstaller())
            {
                Console.WriteLine("Checking requirements...\r\n");
                if (AmeliorationUtil.Playbook.Requirements.Contains(Requirements.Requirement.Internet) && !await (new Requirements.Internet()).IsMet())
                {
                    Console.WriteLine("Internet must be connected to run this Playbook.");
                }

                if (AmeliorationUtil.Playbook.Requirements.Contains(Requirements.Requirement.DefenderDisabled) && Process.GetProcessesByName("MsMpEng").Any())
                {
                    bool first = true;

                    while ((await GetDefenderToggles()).Any(x => x))
                    {
                        Console.WriteLine(
                            "All 4 windows security toggles must be set to off.\r\nNavigate to Windows Security > Virus & threat detection > manage settings.\r\nPress any key to continue...\r\n");
                        Console.ReadKey();
                    }

                    bool remnantsOnly = false;

                    Console.WriteLine(remnantsOnly
                        ? "The system must be prepared before continuing.\r\nPress any key to continue..."
                        : "The system must be prepared before continuing. Your system will restart after preparation\r\nPress any key to continue...");
                    Console.ReadKey();
                    try
                    {
                        Console.WriteLine("\r\nPreparing system...");
                        await PrepareSystemCLI(false);
                        Console.WriteLine("Preparation Complete");

                        if (!remnantsOnly)
                        {
                            Console.WriteLine("\r\nRestarting system...");
                            CmdAction reboot = new CmdAction()
                            {
                                Command = "timeout /t 1 & shutdown /r /t 0",
                                Wait = false
                            };

                            Wrap.ExecuteSafe(() => reboot.RunTaskOnMainThread(Output.OutputWriter.Null));

                            Environment.Exit(0);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Error preparing system: " + e.Message);
                        Environment.Exit(-1);
                    }
                }

                if (AmeliorationUtil.Playbook.Requirements.Contains(Requirements.Requirement.Internet) && !await (new Requirements.Internet()).IsMet())
                {
                    Console.WriteLine("Internet must be connected to run this Playbook.");
                }
            }

            if (!File.Exists($"{AmeliorationUtil.Playbook.Path}\\options.txt"))
            {
                List<string> defaultOptions = new List<string>();
                foreach (var page in AmeliorationUtil.Playbook.FeaturePages)
                {
                    if (page.DependsOn != null && !defaultOptions.Contains(page.DependsOn))
                        continue;

                    if (page.GetType() == typeof(Playbook.CheckboxPage))
                    {
                        foreach (var option in ((Playbook.CheckboxPage)page).Options.Where(x => ((Playbook.CheckboxPage.CheckboxOption)x).IsChecked))
                        {
                            defaultOptions.Add(option.Name);
                        }
                    }

                    if (page.GetType() == typeof(Playbook.RadioPage))
                        defaultOptions.Add(((Playbook.RadioPage)page).DefaultOption);
                    if (page.GetType() == typeof(Playbook.RadioImagePage))
                        defaultOptions.Add(((Playbook.RadioImagePage)page).DefaultOption);
                }

                AmeliorationUtil.Playbook.Options = defaultOptions;
            }

            if (!AmeliorationUtil.Playbook.UseKernelDriver.HasValue)
            {
                if (new RegistryValueAction()
                    {
                        KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                        Value = "Enabled",
                        Data = 1,
                    }.GetStatus(Output.OutputWriter.Null)
                    != UninstallTaskStatus.Completed
                    &&
                    new RegistryValueAction()
                    {
                        KeyName = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                        Value = "VulnerableDriverBlocklistEnable",
                        Data = 0,
                    }.GetStatus(Output.OutputWriter.Null)
                    == UninstallTaskStatus.Completed && (await GetDefenderToggles()).All(toggleOn => !toggleOn))
                {
                    AmeliorationUtil.UseKernelDriver = true;
                }
            }
            else
                AmeliorationUtil.UseKernelDriver = AmeliorationUtil.Playbook.UseKernelDriver.Value;

            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ame-assassin")))
                {
                    Console.WriteLine("Extracting resources");

                    ExtractResourceFolder("resources", Directory.GetCurrentDirectory());
                    ExtractArchive(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CLI-Resources.7z"), AppDomain.CurrentDomain.BaseDirectory);
                    if (AmeliorationUtil.UseKernelDriver)
                        ExtractArchive(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ProcessInformer.7z"), AppDomain.CurrentDomain.BaseDirectory);
                    try
                    {
                        File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CLI-Resources.7z"));
                        File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ProcessInformer.7z"));
                    }
                    catch (Exception e)
                    {
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error extracting resources.");
                return -1;
            }

            var launchResult = await SafeTask.Run(
                () => InterLink.LaunchNode(TargetLevel.Administrator,
                    arguments => NativeProcess.StartProcessAsTI(Win32.ProcessEx.GetCurrentProcessFileLocation(), arguments), Level.TrustedInstaller, Mode.TwoWay,
                    Process.GetCurrentProcess().Id, false),
                true);
            if (launchResult.Failed)
            {
                Console.WriteLine("Could not initialize process. Check the error logs and contact the team " + "for more information and assistance.");
                Environment.Exit(1);
            }

            List<string> options = null;
            if (args.Length > 1)
            {
                options = args.Skip(1).ToList();
            }

            var status = "Starting Playbook";
            bool errorsOccurred = false;
            try
            {
                using (var reporter = new InterLink.InterMessageReporter(statusText => { status = statusText.TrimEnd('.') + "..."; }))
                {
                    using (var progress = new InterLink.InterProgress(async value => { Console.WriteLine(value + "% " + status + "..."); }))
                    {
                        errorsOccurred = await InterLink.ExecuteAsync(() => AmeliorationUtil.RunPlaybook(AmeliorationUtil.Playbook.Path, options.ToArray(),
                            Environment.CurrentDirectory, progress, reporter, AmeliorationUtil.UseKernelDriver));
                    }
                }
            }
            catch (Exception exception)
            {
                InterLink.ShutdownNode(Level.TrustedInstaller);

                if (exception is SerializableException serializableException && serializableException.OriginalType.Type == typeof(SerializationException))
                {
                    Console.WriteLine("\r\nYAML Error: " + exception.ToString());
                    Environment.Exit(1);
                }

                Console.WriteLine("\r\nFatal Playbook Error: " + exception.ToString());
                Environment.Exit(1);
            }

            if (errorsOccurred)
                Console.WriteLine("\r\nPlaybook completed with errors.");
            else
                Console.WriteLine("\r\nPlaybook completed successfully.");

            return 0;
        }

        public static void ExtractArchive(string file, string targetDir)
        {
            RunCommand($"x \"{file}\" -o\"{targetDir}\" -p\"wizard\" -y -aos");
        }

        private static void RunCommand(string command)
        {
            var proc = new Process();
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Normal,
                Arguments = command,
                FileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "7za.exe"),
                RedirectStandardError = true,
            };

            proc.StartInfo = startInfo;

            proc.Start();
            StringBuilder errorOutput = new StringBuilder("");

            proc.ErrorDataReceived += (sender, args) => { errorOutput.Append("\r\n" + args.Data); };
            proc.BeginErrorReadLine();

            proc.WaitForExit();

            proc.CancelErrorRead();

            if (proc.ExitCode == 1)
                Log.EnqueueSafe(LogType.Error, "Warning while running 7zip: " + errorOutput.ToString(), null, ("Command", command));
            if (proc.ExitCode > 1)
                throw new ArgumentOutOfRangeException("Error running 7zip: " + errorOutput.ToString());
        }

        public static void ExtractResourceFolder(string resource, string dir, bool overwrite = false)
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

            Assembly assembly = Assembly.GetExecutingAssembly();

            var resources = assembly.GetManifestResourceNames().Where(res => res.StartsWith($"TrustedUninstaller.CLI.Properties.{resource}."));

            foreach (var obj in resources)
            {
                using (UnmanagedMemoryStream stream = (UnmanagedMemoryStream)assembly.GetManifestResourceStream(obj))
                {
                    int MB = 1024 * 1024;
                    int offset = -MB;

                    var file = dir + $"\\{obj.Substring($"TrustedUninstaller.CLI.Properties.{resource}.".Length).Replace("---", "\\")}";
                    if (file.EndsWith(".gitkeep")) continue;

                    var fileDir = Path.GetDirectoryName(file);
                    if (fileDir != null && !Directory.Exists(fileDir)) Directory.CreateDirectory(fileDir);

                    if (File.Exists(file) && !overwrite) continue;
                    if (File.Exists(file) && overwrite)
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch (Exception e)
                        {
                            if (!Directory.Exists(Directory.GetCurrentDirectory() + "\\Logs"))
                                Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\Logs");
                            using (var writer = new StreamWriter(Path.Combine(Directory.GetCurrentDirectory(), "Logs\\ErrorLog.txt"), true))
                            {
                                writer.WriteLine($"Title: Could not delete existing resource file {file}.\r\nMessage: {e.Message}\r\n\r\nStackTrace: {e.StackTrace}");
                                writer.WriteLine("\r\nDate/Time: " + DateTime.Now);
                                writer.WriteLine("============================================");
                            }

                            continue;
                        }
                    }

                    using (FileStream fsDlst = new FileStream(file, FileMode.CreateNew, FileAccess.Write))
                    {
                        while (offset + MB < stream.Length)
                        {
                            var buffer = new byte[MB];
                            offset += MB;

                            if (offset + MB > stream.Length)
                            {
                                var bytesLeft = stream.Length - offset;
                                buffer = new byte[bytesLeft];
                            }

                            stream.Seek(offset, SeekOrigin.Begin);
                            stream.Read(buffer, 0, buffer.Length);

                            fsDlst.Seek(offset, SeekOrigin.Begin);
                            fsDlst.Write(buffer, 0, buffer.Length);
                        }
                    }
                }
            }
        }

        public static async Task<List<bool>> GetDefenderToggles()
        {
            var result = new List<bool>();

            await Task.Run(() =>
            {
                var defenderKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender");
                var policiesKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender");

                RegistryKey realtimePolicy = null;
                RegistryKey realtimeKey = null;
                try
                {
                    try
                    {
                        realtimePolicy = policiesKey.OpenSubKey("Real-Time Protection");
                    }
                    catch (Exception e)
                    {
                    }

                    if (realtimePolicy != null)
                        realtimeKey = realtimePolicy;
                    else
                        realtimeKey = defenderKey.OpenSubKey("Real-Time Protection");
                }
                catch
                {
                    result.Add(false);
                }

                if (realtimeKey != null)
                {
                    try
                    {
                        result.Add((int)realtimeKey.GetValue("DisableRealtimeMonitoring") != 1);
                    }
                    catch (Exception exception)
                    {
                        try
                        {
                            realtimeKey = defenderKey.OpenSubKey("Real-Time Protection");
                            result.Add((int)realtimeKey.GetValue("DisableRealtimeMonitoring") != 1);
                        }
                        catch (Exception e)
                        {
                            result.Add(true);
                        }
                    }
                }

                try
                {
                    RegistryKey spynetPolicy = null;
                    RegistryKey spynetKey = null;

                    try
                    {
                        spynetPolicy = policiesKey.OpenSubKey("SpyNet");
                    }
                    catch (Exception e)
                    {
                    }

                    if (spynetPolicy != null)
                        spynetKey = spynetPolicy;
                    else
                        spynetKey = defenderKey.OpenSubKey("SpyNet");

                    int reporting = 0;
                    int consent = 0;
                    try
                    {
                        reporting = (int)spynetKey.GetValue("SpyNetReporting");
                    }
                    catch (Exception e)
                    {
                        if (spynetPolicy != null)
                        {
                            reporting = (int)defenderKey.OpenSubKey("SpyNet").GetValue("SpyNetReporting");
                        }
                    }

                    try
                    {
                        consent = (int)spynetKey.GetValue("SubmitSamplesConsent");
                    }
                    catch (Exception e)
                    {
                        if (spynetPolicy != null)
                        {
                            consent = (int)defenderKey.OpenSubKey("SpyNet").GetValue("SubmitSamplesConsent");
                        }
                    }

                    result.Add(reporting != 0);
                    result.Add(consent != 0 && consent != 2 && consent != 4);
                }
                catch
                {
                    result.Add(false);
                    result.Add(false);
                }

                try
                {
                    int tamper = (int)defenderKey.OpenSubKey("Features").GetValue("TamperProtection");
                    result.Add(tamper != 4 && tamper != 0);
                }
                catch
                {
                    result.Add(false);
                }
            });
            return result;
        }

        public static async Task PrepareSystemCLI(bool KernelDriverOnly)
        {
            var status = "Adding certificate";
            using var progress = new InterLink.InterProgress(value => Console.WriteLine(value + "% " + status + "..."));
            using var messageReporter = new InterLink.InterMessageReporter(message => status = message);
            
            var task = KernelDriverOnly ? InterLink.ExecuteAsync(() => Defender.DisableBlocklist()) : InterLink.ExecuteAsync(() => Defender.KillAndDisable(progress, messageReporter, false, true));
            await task;
        }
    }
}