#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization.TypeResolvers;

namespace TrustedUninstaller.Shared.Parser
{
    public class TaskComparer : IComparer<UninstallTask> {
        public int Compare(UninstallTask x, UninstallTask y)
        {
            return ReferenceEquals(x, y) ? 0 : x.Priority.CompareTo(y.Priority);
        }
    }

    public class ConfigParser
    {
        public List<UninstallTask> Tasks { get; set; }

        private IDeserializer Deserializer { get; }

        private ISerializer Serializer { get; }

        public ConfigParser()
        {
            Tasks = new List<UninstallTask>();
            Deserializer = new DeserializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .WithTagMapping("!file", typeof(FileAction))
                .WithTagMapping("!service", typeof(ServiceAction))
                .WithTagMapping("!registryKey", typeof(RegistryKeyAction))
                .WithTagMapping("!registryValue", typeof(RegistryValueAction))
                .WithTagMapping("!appx", typeof(AppxAction))
                .WithTagMapping("!systemPackage", typeof(SystemPackageAction))
                .WithTagMapping("!lineInFile", typeof(LineInFileAction))
                .WithTagMapping("!scheduledTask", typeof(ScheduledTaskAction))
                .WithTagMapping("!user", typeof(UserAction))
                .WithTagMapping("!run", typeof(RunAction))
                .WithTagMapping("!powerShell", typeof(PowerShellAction))
                .WithTagMapping("!shortcut", typeof(ShortcutAction))
                .WithTagMapping("!cmd", typeof(CmdAction))
                .WithTagMapping("!uninstallTask", typeof(UninstallTask))
                .WithTagMapping("!taskKill", typeof(TaskKillAction))
                .WithTagMapping("!update", typeof(UpdateAction))
                .WithTagMapping("!writeStatus", typeof(WriteStatusAction))
                .WithNodeTypeResolver(new TaskActionResolver())
                .Build();

            Serializer = new SerializerBuilder()
                .WithNamingConvention(CamelCaseNamingConvention.Instance)
                .WithTagMapping("!file", typeof(FileAction))
                .WithTagMapping("!service", typeof(ServiceAction))
                .WithTagMapping("!registryKey", typeof(RegistryKeyAction))
                .WithTagMapping("!registryValue", typeof(RegistryValueAction))
                .WithTagMapping("!appx", typeof(AppxAction))
                .WithTagMapping("!systemPackage", typeof(SystemPackageAction))
                .WithTagMapping("!lineInFile", typeof(LineInFileAction))
                .WithTagMapping("!scheduledTask", typeof(ScheduledTaskAction))
                .WithTagMapping("!user", typeof(UserAction))
                .WithTagMapping("!run", typeof(RunAction))
                .WithTagMapping("!powerShell", typeof(PowerShellAction))
                .WithTagMapping("!shortcut", typeof(ShortcutAction))
                .WithTagMapping("!cmd", typeof(CmdAction))
                .WithTagMapping("!uninstallTask", typeof(UninstallTask))
                .WithTagMapping("!taskKill", typeof(TaskKillAction))
                .WithTagMapping("!update", typeof(UpdateAction))
                .WithTagMapping("!writeStatus", typeof(WriteStatusAction))
                .WithTypeResolver(new DynamicTypeResolver())
                .EnsureRoundtrip()
                .Build();
        }

        public void SerializeItem(TextWriter tw, object item)
        {
            Serializer.Serialize(tw, item);
        }
        
        public bool Add(string filename)
        {
            var configData = File.ReadAllText(filename);
            var taskData = Deserializer.Deserialize<UninstallTask>(configData);

            if (taskData.SupportedBuilds != null && !taskData.SupportedBuilds.Contains(Globals.WinVer.ToString()))
            {
                return false;
            }
            
            taskData.Update();
            Tasks.Add(taskData);
            return true;
        }
    }
}
