#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Core.Exceptions;
using YamlDotNet.Serialization;


namespace Core.Actions
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

    public class RegistryValueAction : ICoreAction
    {
        [YamlMember(typeof(string), Alias = "path")]
        public string KeyName { get; set; }

        [YamlMember(typeof(string), Alias = "value")]
        public string Value { get; set; } = "";
        
        [YamlMember(typeof(object), Alias = "data")]
        public object? Data { get; set; }
        
        [YamlMember(typeof(RegistryValueType), Alias = "type")]
        public RegistryValueType Type { get; set; }

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
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"RegistryValueAction failed to {Operation.ToString().ToLower()} value '{Value}' in key '{KeyName}'";
        
        private List<RegistryKey> GetRoots()
        {
            var hive = KeyName.Split('\\').GetValue(0).ToString().ToUpper();
            var list = new List<RegistryKey>();

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

        public UninstallTaskStatus GetStatus()
        {
            try
            {
                var roots = GetRoots();

                foreach (var _root in roots)
                {
                    var root = _root;
                    var subKey = GetSubKey();
                    
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
                Log.EnqueueExceptionSafe(e);
                return UninstallTaskStatus.ToDo;
            }

            return UninstallTaskStatus.Completed;
        }

        public void RunTask(bool logExceptions = true)
        {
            
            var roots = GetRoots();

            foreach (var _root in roots)
            {
                var root = _root;
                var subKey = GetSubKey();
                try
                {
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
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(e, ("Key", root?.Name + "\\" + subKey), ("Value", Value));
                }
            }
            return;
        }
    }
}
