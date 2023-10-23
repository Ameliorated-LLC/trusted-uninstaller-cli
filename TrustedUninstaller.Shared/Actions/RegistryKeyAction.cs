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
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;


namespace TrustedUninstaller.Shared.Actions
{
    public enum RegistryKeyOperation
    {
        Delete = 0,
        Add = 1
    }
    public class RegistryKeyAction : TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread() { throw new NotImplementedException(); }
        [YamlMember(typeof(string), Alias = "path")]
        public string KeyName { get; set; }

        [YamlMember(typeof(Scope), Alias = "scope")]
        public Scope Scope { get; set; } = Scope.AllUsers;

        [YamlMember(typeof(RegistryKeyOperation), Alias = "operation")]
        public RegistryKeyOperation Operation { get; set; } = RegistryKeyOperation.Delete;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        
        static Dictionary<RegistryHive, UIntPtr> HiveKeys = new Dictionary<RegistryHive, UIntPtr> {
            { RegistryHive.ClassesRoot, new UIntPtr(0x80000000u) },
            { RegistryHive.CurrentConfig, new UIntPtr(0x80000005u) },
            { RegistryHive.CurrentUser, new UIntPtr(0x80000001u) },
            { RegistryHive.DynData, new UIntPtr(0x80000006u) },
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

        public UninstallTaskStatus GetStatus()
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
                ErrorLogger.WriteToErrorLog(e.Message,
                    e.StackTrace, "RegistryKeyAction Error");
                return UninstallTaskStatus.ToDo;
            }
            return UninstallTaskStatus.Completed;
        }

        public async Task<bool> RunTask()
        {
            Console.WriteLine($"{Operation.ToString().TrimEnd('e')}ing registry key '{KeyName}'...");
            
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
                            ErrorLogger.WriteToErrorLog($"User classes hive not found for hive {_root.Name}.",
                                Environment.StackTrace, "RegistryKeyAction Error");
                            continue;
                        }
                    }

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
                            ErrorLogger.WriteToErrorLog(e.GetType() + ": " + e.Message,
                                e.StackTrace, "RegistryKeyAction Warning", root?.Name + "\\" + subKey);

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
                    ErrorLogger.WriteToErrorLog(e.Message,
                        e.StackTrace, "RegistryKeyAction Error", root?.Name + "\\" + subKey);
                }
            }
            return true;
        }
    }
}
