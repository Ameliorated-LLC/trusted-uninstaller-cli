#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Core.Exceptions;
using YamlDotNet.Serialization;


namespace Core.Actions
{
    public enum RegistryKeyOperation
    {
        Delete = 0,
        Add = 1
    }
    public class RegistryKeyAction : ICoreAction
    {
        public void RunTaskOnMainThread() { throw new NotImplementedException(); }
        [YamlMember(typeof(string), Alias = "path")]
        public string KeyName { get; set; }

        [YamlMember(typeof(RegistryKeyOperation), Alias = "operation")]
        public RegistryKeyOperation Operation { get; set; } = RegistryKeyOperation.Delete;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        
        static Dictionary<RegistryHive, UIntPtr> HiveKeys = new Dictionary<RegistryHive, UIntPtr> {
            { RegistryHive.ClassesRoot, new UIntPtr(0x80000000u) },
            { RegistryHive.CurrentConfig, new UIntPtr(0x80000005u) },
            { RegistryHive.CurrentUser, new UIntPtr(0x80000001u) },
            //{ RegistryHive.DynData, new UIntPtr(0x80000006u) },
            { RegistryHive.LocalMachine, new UIntPtr(0x80000002u) },
            { RegistryHive.PerformanceData, new UIntPtr(0x80000004u) },
            { RegistryHive.Users, new UIntPtr(0x80000003u) }
        };
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
  
        [DllImport("advapi32.dll", EntryPoint = "RegDeleteKeyEx", SetLastError = true)]
        private static extern int RegDeleteKeyEx(
            UIntPtr hKey,
            string lpSubKey,
            uint samDesired, // see Notes below
            uint Reserved);
        private static void DeleteKeyTreeWin32(string key, RegistryHive hive)
        {
            var openedKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(key);
            if (openedKey == null)
                return;

            openedKey.GetSubKeyNames().ToList().ForEach(subKey => DeleteKeyTreeWin32(key + "\\" + subKey, hive));
            openedKey.Close();

            RegDeleteKeyEx(HiveKeys[hive], key, 0x0100, 0);
        }
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"RegistryKeyAction failed to {Operation.ToString().ToLower()} key '{KeyName}'.";
        
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

                    if (Operation == RegistryKeyOperation.Delete && openedSubKey != null)
                    {
                        return UninstallTaskStatus.ToDo;
                    }
                    if (Operation == RegistryKeyOperation.Add && openedSubKey == null)
                    {
                        return UninstallTaskStatus.ToDo;
                    }
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
                    if (Operation == RegistryKeyOperation.Add && root.OpenSubKey(subKey) == null)
                    {
                        root.CreateSubKey(subKey);
                    }
                    if (Operation == RegistryKeyOperation.Delete)
                    {
                        try
                        {
                            root.DeleteSubKeyTree(subKey, false);
                        }
                        catch (Exception e)
                        {
                            Log.EnqueueExceptionSafe(LogType.Warning, e, ("Key", root?.Name + "\\" + subKey));

                            var rootHive = root.Name.Split('\\').First() switch
                            {
                                "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
                                "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
                                "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
                                "HKEY_USERS" => RegistryHive.Users,
                                _ => throw new ArgumentException($"Unable to parse: " + root.Name.Split('\\').First())
                            };
                            
                            DeleteKeyTreeWin32(root.Name.StartsWith("HKEY_USERS") ? root.Name.Split('\\')[1] + "\\" + subKey: subKey, rootHive);
                        }
                    }
                }
                catch (Exception e)
                {
                    if (logExceptions)
                        Log.EnqueueExceptionSafe(e, ("Key", root?.Name + "\\" + subKey));
                }
            }
        }
    }
}
