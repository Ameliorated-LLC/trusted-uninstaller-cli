#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Core;
using Microsoft.Win32;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;


namespace TrustedUninstaller.Shared.Actions
{
    public enum RegistryValueOperation
    {
        Delete = 0,
        Add = 1,
        // This indicates to skip the action if the specified value does not already exist
        Set = 2
    }

    public enum RegistryValueType
    {
        REG_SZ = RegistryValueKind.String,
        REG_MULTI_SZ = RegistryValueKind.MultiString,
        REG_EXPAND_SZ = RegistryValueKind.ExpandString,
        REG_DWORD = RegistryValueKind.DWord,
        REG_QWORD = RegistryValueKind.QWord,
        REG_BINARY = RegistryValueKind.Binary,
        REG_NONE = RegistryValueKind.None,
        REG_UNKNOWN = RegistryValueKind.Unknown
    }

    public class RegistryValueAction : TaskActionWithOutputProcessor, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        [YamlMember(typeof(string), Alias = "path")]
        public string KeyName { get; set; }

        [YamlMember(typeof(string), Alias = "value")]
        public string Value { get; set; } = "";
        
        [YamlMember(typeof(object), Alias = "data")]
        public object? Data { get; set; }
        
        [YamlMember(typeof(RegistryValueType), Alias = "type")]
        public RegistryValueType Type { get; set; }
        
        [YamlMember(typeof(Scope), Alias = "scope")]
        public Scope Scope { get; set; } = Scope.AllUsers;

        [YamlMember(typeof(RegistryValueOperation), Alias = "operation")]
        public RegistryValueOperation Operation { get; set; } = RegistryValueOperation.Add;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight()
        {
            /*
            int roots;
            try
            {
                roots = GetRoots().Count;
            }
            catch (Exception e)
            {

                roots = 1;
            }
            */

            return ProgressWeight;
        }
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => true;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"RegistryValueAction failed to {Operation.ToString().ToLower()} value '{Value}' in key '{KeyName}'";
        
        private List<RegistryKey> GetRoots()
        {
            var hive = KeyName.Split('\\').GetValue(0).ToString().ToUpper();
            var list = new List<RegistryKey>();

            if (hive.Equals("HKCU") || hive.Equals("HKEY_CURRENT_USER"))
            {
                RegistryKey usersKey;
                List<string> userKeys;

                switch (Scope)
                {
                    case Scope.AllUsers:
                        WinUtil.RegistryManager.HookUserHives();
                    
                        usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                        userKeys = usersKey.GetSubKeyNames().
                            Where(x => x.StartsWith("S-") && 
                                usersKey.OpenSubKey(x).GetSubKeyNames().Any(y => y.Equals("Volatile Environment"))).ToList();
                    
                        userKeys.AddRange(usersKey.GetSubKeyNames().Where(x => x.StartsWith("AME_UserHive_") && !x.EndsWith("_Classes")).ToList());
                    
                        userKeys.ForEach(x => list.Add(usersKey.OpenSubKey(x, true)));
                        return list;
                    case Scope.ActiveUsers:
                        usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                        userKeys = usersKey.GetSubKeyNames().
                            Where(x => x.StartsWith("S-") && 
                                usersKey.OpenSubKey(x).GetSubKeyNames().Any(y => y.Equals("Volatile Environment"))).ToList();

                        userKeys.ForEach(x => list.Add(usersKey.OpenSubKey(x, true)));
                        return list;
                    case Scope.DefaultUser:
                        usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                        userKeys = usersKey.GetSubKeyNames().Where(x => x.Equals("AME_UserHive_Default") && !x.EndsWith("_Classes")).ToList();
                        
                        userKeys.ForEach(x => list.Add(usersKey.OpenSubKey(x, true)));
                        return list;
                }
            }
            list.Add(hive switch
            {
                "HKCU" => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default),
                "HKEY_CURRENT_USER" => RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default),
                "HKLM" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default),
                "HKEY_LOCAL_MACHINE" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default),
                "HKCR" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default),
                "HKEY_CLASSES_ROOT" => RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default),
                "HKU" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default),
                "HKEY_USERS" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default),
                _ => throw new ArgumentException($"Key '{KeyName}' does not specify a valid registry hive.")
            });
            return list;
        }

        public string GetSubKey() => KeyName.Substring(KeyName.IndexOf('\\') + 1);

        private RegistryKey? OpenSubKey(RegistryKey root)
        {
            var subKeyPath = GetSubKey();
            
            if (subKeyPath == null) throw new ArgumentException($"Key '{KeyName}' is invalid.");
            
            return root.OpenSubKey(subKeyPath, true);
        }

        public object? GetCurrentValue(RegistryKey root)
        {
            var subkey = GetSubKey();
            return Registry.GetValue(root.Name + "\\" + subkey, Value, null);
        }
        
        public static byte[] StringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            try
            {
                var roots = GetRoots();

                foreach (var _root in roots)
                {
                    var root = _root;
                    var subKey = GetSubKey();
                    
                    if (root.Name.Contains("AME_UserHive_") && subKey.StartsWith("SOFTWARE\\Classes", StringComparison.CurrentCultureIgnoreCase))
                    {
                        var usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);

                        root = usersKey.OpenSubKey(root.Name.Substring(11) + "_Classes", true);
                        subKey = Regex.Replace(subKey, @"^SOFTWARE\\*Classes\\*", "", RegexOptions.IgnoreCase);

                        if (root == null)
                        {
                            continue;
                        }
                    }
                    
                    var openedSubKey = root.OpenSubKey(subKey);

                    if (openedSubKey == null && (Operation == RegistryValueOperation.Set || Operation == RegistryValueOperation.Delete))
                        continue;
                    if (openedSubKey == null) return UninstallTaskStatus.ToDo;

                    var value = openedSubKey.GetValue(Value);

                    if (value == null)
                    {
                        if (Operation == RegistryValueOperation.Set || Operation == RegistryValueOperation.Delete)
                            continue;

                        return UninstallTaskStatus.ToDo;
                    }
                    if (Operation == RegistryValueOperation.Delete) return UninstallTaskStatus.ToDo;

                    if (Data == null) return UninstallTaskStatus.ToDo;


                    bool matches;
                    try
                    {
                        matches = Type switch
                        {
                            RegistryValueType.REG_SZ =>
                                Data.ToString() == value.ToString(),
                            RegistryValueType.REG_EXPAND_SZ =>
                                // RegistryValueOptions.DoNotExpandEnvironmentNames above did not seem to work.
                                Environment.ExpandEnvironmentVariables(Data.ToString()) == value.ToString(),
                            RegistryValueType.REG_MULTI_SZ =>
                                Data.ToString() == "" ?
                                    ((string[])value).SequenceEqual(new string[] { }) :
                                    ((string[])value).SequenceEqual(Data.ToString().Split(new string[] { "\\0" }, StringSplitOptions.None)),
                            RegistryValueType.REG_DWORD =>
                                unchecked((int)Convert.ToUInt32(Data)) == (int)value,
                            RegistryValueType.REG_QWORD =>
                                Convert.ToUInt64(Data) == (ulong)value,
                            RegistryValueType.REG_BINARY =>
                                ((byte[])value).SequenceEqual(StringToByteArray(Data.ToString())),
                            RegistryValueType.REG_NONE =>
                                ((byte[])value).SequenceEqual(new byte[0]),
                            RegistryValueType.REG_UNKNOWN =>
                                Data.ToString() == value.ToString(),
                            _ => throw new ArgumentException("Impossible.")
                        };
                    }
                    catch (InvalidCastException)
                    {
                        matches = false;
                    }
                    if (!matches) return UninstallTaskStatus.ToDo;
                }
            }
            catch (Exception e)
            {
                Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                return UninstallTaskStatus.ToDo;
            }

            return UninstallTaskStatus.Completed;
        }

        public async Task<bool> RunTask(Output.OutputWriter output)
        {

            output.WriteLineSafe("Info", $"{Operation.ToString().TrimEnd('e')}ing value '{Value}' in key '{KeyName}'...");
            
            var roots = GetRoots();

            foreach (var _root in roots)
            {
                var root = _root;
                var subKey = GetSubKey();
                try
                {
                    if (root.Name.Contains("AME_UserHive_") && subKey.StartsWith("SOFTWARE\\Classes", StringComparison.CurrentCultureIgnoreCase))
                    {
                        var usersKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);

                        root = usersKey.OpenSubKey(root.Name.Substring(11) + "_Classes", true);
                        subKey = Regex.Replace(subKey, @"^SOFTWARE\\*Classes\\*", "", RegexOptions.IgnoreCase);

                        if (root == null)
                        {
                            Log.WriteSafe(LogType.Warning, $"User classes hive not found for hive {_root.Name}.", new SerializableTrace(), output.LogOptions);
                            continue;
                        }
                    }

                    if (GetCurrentValue(root) == Data) continue;

                    if (root.OpenSubKey(subKey) == null && Operation == RegistryValueOperation.Set) continue;
                    if (root.OpenSubKey(subKey) == null && Operation == RegistryValueOperation.Add) root.CreateSubKey(subKey);

                    if (Operation == RegistryValueOperation.Delete)
                    {
                        var key = root.OpenSubKey(subKey, true);
                        key?.DeleteValue(Value);
                        continue;
                    }

                    if (Type == RegistryValueType.REG_BINARY)
                    {
                        var data = StringToByteArray(Data.ToString());

                        Registry.SetValue(root.Name + "\\" + subKey, Value, data, (RegistryValueKind)Type);
                    }
                    else if (Type == RegistryValueType.REG_DWORD)
                    {
                        // DWORD values using the highest bit set fail without this, for example '2962489444'.
                        // See https://stackoverflow.com/questions/6608400/how-to-put-a-dword-in-the-registry-with-the-highest-bit-set;
                        var value = unchecked((int)Convert.ToUInt32(Data));
                        Registry.SetValue(root.Name + "\\" + subKey, Value, value, (RegistryValueKind)Type);
                    }
                    else if (Type == RegistryValueType.REG_QWORD)
                    {
                        Registry.SetValue(root.Name + "\\" + subKey, Value, Convert.ToUInt64(Data), (RegistryValueKind)Type);
                    }
                    else if (Type == RegistryValueType.REG_NONE)
                    {
                        byte[] none = new byte[0];

                        Registry.SetValue(root.Name + "\\" + subKey, Value, none, (RegistryValueKind)Type);
                    }
                    else if (Type == RegistryValueType.REG_MULTI_SZ)
                    {
                        string[] data;
                        if (Data.ToString() == "") data = new string[] { };
                        else data = Data.ToString().Split(new string[] { "\\0" }, StringSplitOptions.None);

                        Registry.SetValue(root.Name + "\\" + subKey, Value, data, (RegistryValueKind)Type);
                    }
                    else
                    {
                        Registry.SetValue(root.Name + "\\" + subKey, Value, Data, (RegistryValueKind)Type);
                    }
                }
                catch (Exception e)
                {
                    Log.WriteExceptionSafe(LogType.Warning, e, output.LogOptions);
                    if (e is UnauthorizedAccessException)
                    {
                        try
                        {
                            var tempPath = Environment.ExpandEnvironmentVariables(@"%TEMP%\AME");
                            var regPath = Environment.ExpandEnvironmentVariables(@"%SYSTEMROOT%\System32\reg.exe");
                            var ameRegPath = Path.Combine(tempPath, "amereg.exe");
                            if (File.Exists(regPath))
                            {
                                if (!Directory.Exists(tempPath))
                                    Directory.CreateDirectory(tempPath);
                                
                                File.Copy(regPath, ameRegPath);
                                
                                RegAddValue(output, ameRegPath, root!.Name + "\\" + subKey, Value, Type, Data?.ToString() ?? null);
                                
                                File.Delete(ameRegPath);
                            }
                            else
                            {
                                output.WriteLineSafe("Info", "reg.exe not found, cannot try alternate method.");
                            }
                        }
                        catch (Exception exception)
                        {
                            Log.WriteExceptionSafe(LogType.Warning, exception, output.LogOptions);
                        }
                    }
                }
            }
            return true;
        }

        private void RegAddValue(Output.OutputWriter output, string exePath, string key, string value, RegistryValueType type, string? data)
        {
            var arguments = @$"add ""{key}"" /v ""{value}"" /t ""{type.ToString()}"" /d ""{data.ToString()}"" /f";
            
            var startInfo = new ProcessStartInfo
            {
                CreateNoWindow = false,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Normal,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                FileName = exePath,
                Arguments = arguments,
            };
            using var process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

            using (var handler = new OutputHandler("Process", process, output))
            {
                handler.StartProcess();

                bool exited = process.WaitForExit(30000);

                // WaitForExit alone seems to not be entirely reliable
                while (!exited && ExeRunning(process.ProcessName, process.Id))
                {
                    exited = process.WaitForExit(30000);
                }
            }

            int exitCode = Wrap.ExecuteSafe(() => process.ExitCode, true, output.LogOptions).Value;
            if (exitCode != 0)
                output.WriteLineSafe("Warning", $"Reg exited with a non-zero exit code: {exitCode}");
        }
    }
}
