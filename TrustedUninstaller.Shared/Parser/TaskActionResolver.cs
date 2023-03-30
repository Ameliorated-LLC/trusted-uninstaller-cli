
using System;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Parser
{
    internal class TaskActionResolver : INodeTypeResolver
    {
        public bool Resolve(NodeEvent? nodeEvent, ref Type currentType)
        {
            if (!currentType.IsInterface || currentType != typeof(ITaskAction))
            {
                return false;
            }


            switch (nodeEvent?.Tag.Value)
            {
                case "!file:":
                    currentType = typeof(FileAction);
                    return true;
                case "!service:":
                    currentType = typeof(ServiceAction);
                    return true;
                case "!user:":
                    currentType = typeof(UserAction);
                    return true;
                case "!run:":
                    currentType = typeof(RunAction);
                    return true;
                case "!powerShell:":
                    currentType = typeof(PowerShellAction);
                    return true;
                case "!shortcut:":
                    currentType = typeof(ShortcutAction);
                    return true;
                case "!cmd:":
                    currentType = typeof(CmdAction);
                    return true;
                case "!scheduledTask:":
                    currentType = typeof(ScheduledTaskAction);
                    return true;
                case "!lineInFile:":
                    currentType = typeof(LineInFileAction);
                    return true;
                case "!registryKey:":
                    currentType = typeof(RegistryKeyAction);
                    return true;
                case "!registryValue:":
                    currentType = typeof(RegistryValueAction);
                    return true;
                case "!appx:":
                    currentType = typeof(AppxAction);
                    return true;
                case "!systemPackage:":
                    currentType = typeof(SystemPackageAction);
                    return true;
                case "!taskKill:":
                    currentType = typeof(TaskKillAction);
                    return true;
                case "!update:":
                    currentType = typeof(UpdateAction);
                    return true;
                case "!writeStatus:":
                    currentType = typeof(WriteStatusAction);
                    return true;
                default:
                    return false;
            }
        }
    }
}