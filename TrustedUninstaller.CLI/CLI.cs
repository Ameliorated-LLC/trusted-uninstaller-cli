using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using TrustedUninstaller.Shared;
using TrustedUninstaller.Shared.Actions;

namespace TrustedUninstaller.CLI
{
    public class CLI
    {
        private static async System.Threading.Tasks.Task<int> Main(string[] args)
        {
            //Needed after defender removal's reboot, the "current directory" will be set to System32
            //After the auto start up.
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            DualOut.Init();

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
                Console.WriteLine("No Playbook selected: Use the GUI to select a playbook to run.");
                return -1;
            }
            
            AmeliorationUtil.Playbook = await AmeliorationUtil.DeserializePlaybook(args[0]);
            AmeliorationUtil.Playbook.Path = args[0];

            if (!Directory.Exists($"{AmeliorationUtil.Playbook.Path}\\Configuration") || Directory.GetFiles($"{AmeliorationUtil.Playbook.Path}\\Configuration").Length == 0)
            {
                Console.WriteLine("Configuration folder is empty, put YAML files in it and restart the application.");
                Console.WriteLine($"Current directory: {Directory.GetCurrentDirectory()}");
                return -1;
            }
            ExtractResourceFolder("resources", Directory.GetCurrentDirectory());
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
                        Console.WriteLine("All 4 windows security toggles must be set to off.\r\nNavigate to Windows Security > Virus & threat detection > manage settings.\r\nPress any key to continue...");
                        Console.ReadKey();
                    }
                    Console.WriteLine("The system must be prepared before continuing Your system will restart after preparation\r\nPress any key to continue...");
                    Console.ReadKey();
                    try
                    {
                        WinUtil.PrepareSystemCLI();
                        CmdAction reboot = new CmdAction()
                        {
                            Command = "timeout /t 1 & shutdown /r /t 0",
                            Wait = false
                        };

                        AmeliorationUtil.SafeRunAction(reboot).Wait();

                        Environment.Exit(0);
                    } catch (Exception e)
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
            
            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ame-assassin")))
                {
                    Console.WriteLine(":AME-STATUS: Extracting resources");

                    ExtractResourceFolder("resources", Directory.GetCurrentDirectory());
                    ExtractArchive(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CLI-Resources.7z"), AppDomain.CurrentDomain.BaseDirectory);
                    try
                    {
                        File.Delete(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "CLI-Resources.7z"));
                    }
                    catch (Exception e) { }
                }
            }
            catch (Exception e)
            {
                ErrorLogger.WriteToErrorLog(e.Message,
                    e.StackTrace, "Error extracting resources.");
                
                Console.WriteLine($":AME-Fatal Error: Error extracting resources.");
                return -1;
            }
            
            await AmeliorationUtil.StartAmelioration();
            
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
                ErrorLogger.WriteToErrorLog(errorOutput.ToString(), Environment.StackTrace, "Warning while running 7zip.", command);
            if (proc.ExitCode > 1)
                throw new ArgumentOutOfRangeException("Error running 7zip: " + errorOutput.ToString());
        }
         public static void ExtractResourceFolder(string resource, string dir, bool overwrite = false)
        {
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

            Assembly assembly = Assembly.GetExecutingAssembly();

            var resources = assembly.GetManifestResourceNames().Where(res => res.StartsWith($"TrustedUninstaller.CLI.Properties"));

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
                    catch (Exception e) { }

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
                    catch (Exception e) { }

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
    }
}