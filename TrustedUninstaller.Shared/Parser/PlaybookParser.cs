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
using TaskAction = TrustedUninstaller.Shared.Actions.TaskAction;

namespace TrustedUninstaller.Shared.Parser
{
    public static class PlaybookParser
    {
        public static IDeserializer Deserializer { get; } = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .WithTagMapping("!task", typeof(TaskAction))
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

        /*
        private ISerializer Serializer { get; } = new SerializerBuilder()
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
            */
    }
}
