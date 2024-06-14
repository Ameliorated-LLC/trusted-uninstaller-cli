#nullable enable
using System;
using System.Collections.Specialized;
using System.Configuration.Install;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Core.Exceptions;
using YamlDotNet.Serialization;
using Core;

namespace Core.Actions
{
    public enum ServiceOperation
    {
        Stop,
        Continue,
        Start,
        Pause,
        Delete,
        Change
    }
    public class ServiceAction : ICoreAction
    {
        public void RunTaskOnMainThread() { throw new NotImplementedException(); }
        [YamlMember(typeof(ServiceOperation), Alias = "operation")]
        public ServiceOperation Operation { get; set; } = ServiceOperation.Delete;
        
        [YamlMember(typeof(string), Alias = "name")]
        public string ServiceName { get; set; } = null!;
        
        [YamlMember(typeof(int), Alias = "startup")]
        public int? Startup { get; set; }
        
        [YamlMember(typeof(bool), Alias = "deleteStop")]
        public bool DeleteStop { get; set; } = true;
        
        [YamlMember(typeof(bool), Alias = "deleteUsingRegistry")]
        public bool RegistryDelete { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "device")]
        public bool Device { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 4;
        public int GetProgressWeight() => ProgressWeight;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;

        public string ErrorString() => $"ServiceAction failed to {Operation.ToString().ToLower()} service {ServiceName}.";
        
        private ServiceController? GetService()
        {
            if (ServiceName.EndsWith("*") && ServiceName.StartsWith("*")) return ServiceController.GetServices()
                .FirstOrDefault(service => service.ServiceName.IndexOf(ServiceName.Trim('*'), StringComparison.CurrentCultureIgnoreCase) >= 0);
            if (ServiceName.EndsWith("*")) return ServiceController.GetServices()
                .FirstOrDefault(service => service.ServiceName.StartsWith(ServiceName.TrimEnd('*'), StringComparison.CurrentCultureIgnoreCase));
            if (ServiceName.StartsWith("*")) return ServiceController.GetServices()
                .FirstOrDefault(service => service.ServiceName.EndsWith(ServiceName.TrimStart('*'), StringComparison.CurrentCultureIgnoreCase));
            
            return ServiceController.GetServices()
                .FirstOrDefault(service => service.ServiceName.Equals(ServiceName, StringComparison.CurrentCultureIgnoreCase));
        }
        private ServiceController? GetDevice()
        {
            if (ServiceName.EndsWith("*") && ServiceName.StartsWith("*")) return ServiceController.GetDevices()
                .FirstOrDefault(service => service.ServiceName.IndexOf(ServiceName.Trim('*'), StringComparison.CurrentCultureIgnoreCase) >= 0);
            if (ServiceName.EndsWith("*")) return ServiceController.GetDevices()
                .FirstOrDefault(service => service.ServiceName.StartsWith(ServiceName.TrimEnd('*'), StringComparison.CurrentCultureIgnoreCase));
            if (ServiceName.StartsWith("*")) return ServiceController.GetDevices()
                .FirstOrDefault(service => service.ServiceName.EndsWith(ServiceName.TrimStart('*'), StringComparison.CurrentCultureIgnoreCase));
            
            return ServiceController.GetDevices()
                .FirstOrDefault(service => service.ServiceName.Equals(ServiceName, StringComparison.CurrentCultureIgnoreCase));
        }

        public UninstallTaskStatus GetStatus()
        {
            if (InProgress) return UninstallTaskStatus.InProgress;

            if (Operation == ServiceOperation.Change && Startup.HasValue)
            {
                // TODO: Implement dev log. Example:
                // if (Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}") == null) WriteToDevLog($"Warning: Service name '{ServiceName}' not found in registry.");

                var root = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
                if (root == null) return UninstallTaskStatus.Completed;

                var value = root.GetValue("Start");

                return (int)value == Startup.Value ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            }
            
            ServiceController? serviceController;
            if (Device) serviceController = GetDevice();
            else serviceController = GetService();
            
            if (Operation == ServiceOperation.Delete && RegistryDelete)
            {
                // TODO: Implement dev log. Example:
                // if (Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}") == null) WriteToDevLog($"Warning: Service name '{ServiceName}' not found in registry.");

                var root = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
                return root == null ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            }

            return Operation switch
            {
                ServiceOperation.Stop =>
                    serviceController == null ||
                    serviceController?.Status == ServiceControllerStatus.Stopped
                    || serviceController?.Status == ServiceControllerStatus.StopPending ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo,
                ServiceOperation.Continue =>
                    serviceController == null ||
                    serviceController?.Status == ServiceControllerStatus.Running
                    || serviceController?.Status == ServiceControllerStatus.ContinuePending ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo,
                ServiceOperation.Start =>
                    serviceController?.Status == ServiceControllerStatus.StartPending
                    || serviceController?.Status == ServiceControllerStatus.Running ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo,
                ServiceOperation.Pause =>
                    serviceController == null ||
                    serviceController?.Status == ServiceControllerStatus.Paused
                    || serviceController?.Status == ServiceControllerStatus.PausePending ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo,
                ServiceOperation.Delete =>
                    serviceController == null || Win32.ServiceEx.IsPendingDeleteOrDeleted(serviceController.ServiceName) ?
                        UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo,
                _ => throw new ArgumentOutOfRangeException("Argument out of Range", new ArgumentOutOfRangeException())
            };
        }

        private readonly string[] RegexNoKill = { "DcomLaunch" }; 
        
        public void RunTask(bool logExceptions = true)
        {
            if (Operation == ServiceOperation.Change && !Startup.HasValue) throw new ArgumentException("Startup property must be specified with the change operation.");
            if (Operation == ServiceOperation.Change && (Startup.Value > 4  || Startup.Value < 0)) throw new ArgumentException("Startup property must be between 1 and 4.");

            if (Operation == ServiceOperation.Change)
            {
                var action = new RegistryValueAction()
                {
                    KeyName = $@"HKLM\SYSTEM\CurrentControlSet\Services\{ServiceName}", 
                    Value = "Start", 
                    Data = Startup.Value, 
                    Type = RegistryValueType.REG_DWORD, 
                    Operation = RegistryValueOperation.Set
                };
                action.RunTask();
                
                InProgress = false;
                return;
            }
            
            ServiceController? service;

            if (Device) service = GetDevice();
            else service = GetService();

            if (service == null)
            {
                if (Operation == ServiceOperation.Start)
                    throw new ArgumentException("Service " + ServiceName + " not found.");
                
                return;
            }

            InProgress = true;

            if ((Operation == ServiceOperation.Delete && DeleteStop) || Operation == ServiceOperation.Stop)
            {
                try
                {
                    foreach (ServiceController dependentService in service.DependentServices.Where(x => x.Status != ServiceControllerStatus.Stopped))
                    {
                        if (RegexNoKill.Any(regex => Regex.Match(dependentService.ServiceName, regex, RegexOptions.IgnoreCase).Success))
                            continue;
                        
                        if (dependentService.Status != ServiceControllerStatus.StopPending && dependentService.Status != ServiceControllerStatus.Stopped)
                        {
                            try
                            {
                                dependentService.Stop();
                            }
                            catch (Exception e)
                            {
                                dependentService.Refresh();
                                if (dependentService.Status != ServiceControllerStatus.Stopped && dependentService.Status != ServiceControllerStatus.StopPending && logExceptions)
                                    Log.EnqueueExceptionSafe(LogType.Warning, e, "Dependent service stop failed.", ("Service", ServiceName), ("Dependent Service", dependentService.ServiceName));
                            }
                        }

                        try
                        {
                            dependentService.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(5000));
                        }
                        catch (Exception e)
                        {
                            dependentService.Refresh();
                            if (service.Status != ServiceControllerStatus.Stopped && logExceptions)
                                Log.EnqueueSafe(LogType.Warning, "Dependent service stop timeout exceeded.", null, ("Service", ServiceName), ("Dependent Service", dependentService.ServiceName));
                        }
                        
                        try
                        {
                            var killServ = new TaskKillAction()
                            {
                                ProcessID = Win32.ServiceEx.GetServiceProcessId(dependentService.ServiceName)
                            };
                            killServ.RunTask(logExceptions);
                        }
                        catch (Exception e)
                        {
                            dependentService.Refresh();
                            if (dependentService.Status != ServiceControllerStatus.Stopped && logExceptions)
                                Log.EnqueueSafe(LogType.Warning, "Could not kill dependent service.", null, ("Service", ServiceName), ("Dependent Service", dependentService.ServiceName));
                        }
                    }
                }
                catch (Exception e)
                {
                    if (logExceptions) 
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Unexpected error while killing dependent services.", ("Service", ServiceName));
                }
            }

            if (Operation == ServiceOperation.Delete)
            {
                if (DeleteStop && service.Status != ServiceControllerStatus.StopPending && service.Status != ServiceControllerStatus.Stopped)
                {
                    if (RegexNoKill.Any(regex => Regex.Match(ServiceName, regex, RegexOptions.IgnoreCase).Success))
                    {
                        if (logExceptions) 
                            Log.EnqueueSafe(LogType.Warning, "Skipped stopping critical service.", null, ("Service", ServiceName));
                    }
                    else
                    {

                        try
                        {
                            service.Stop();
                        }
                        catch (Exception e)
                        {
                            service.Refresh();
                            if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending && logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Service stop failed.", ("Service", ServiceName));
                        }

                        try
                        {
                            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(5000));
                        }
                        catch (Exception e)
                        {
                            service.Refresh();
                            if (service.Status != ServiceControllerStatus.Stopped && logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Service stop timeout exceeded.", ("Service", ServiceName));
                        }
                        try
                        {
                            var killServ = new TaskKillAction()
                            {
                                ProcessID = Win32.ServiceEx.GetServiceProcessId(service.ServiceName)
                            };
                            killServ.RunTask(logExceptions);
                        }
                        catch (Exception e)
                        {
                            service.Refresh();
                            if (service.Status != ServiceControllerStatus.Stopped && logExceptions)
                                Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not kill service.", ("Service", ServiceName));
                        }
                    }
                }
                
                if (RegistryDelete)
                {
                    var action = new RegistryKeyAction()
                    {
                        KeyName = $@"HKLM\SYSTEM\CurrentControlSet\Services\{ServiceName}",
                        Operation = RegistryKeyOperation.Delete
                    };
                    action.RunTask();
                }
                else
                {
                    try
                    {
                        ServiceInstaller ServiceInstallerObj = new ServiceInstaller();
                        ServiceInstallerObj.Context = new InstallContext();
                        ServiceInstallerObj.ServiceName = service.ServiceName; 
                        ServiceInstallerObj.Uninstall(null);
                    }
                    catch (Exception e)
                    {
                        if (logExceptions)
                            Log.EnqueueExceptionSafe(LogType.Warning, e, "Service uninstall failed.", ("Service", ServiceName));
                    }
                }

            } else if (Operation == ServiceOperation.Start)
            {
                try
                {
                    service.Start();
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service start failed.", ("Service", ServiceName));
                }
                
                try
                {
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(5000));
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service start timeout exceeded.", ("Service", ServiceName));
                }
            } else if (Operation == ServiceOperation.Stop)
            {
                if (RegexNoKill.Any(regex => Regex.Match(ServiceName, regex, RegexOptions.IgnoreCase).Success))
                {
                    Log.EnqueueSafe(LogType.Warning, "Skipped stopping critical service.", null, ("Service", ServiceName));
                    return;
                }
                
                try
                {
                    service.Stop();
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service stop failed.", ("Service", ServiceName));
                }

                try
                {
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(5000));
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Stopped && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service stop timeout exceeded.", ("Service", ServiceName));
                }
                try
                {
                    var killServ = new TaskKillAction()
                    {
                        ProcessID = Win32.ServiceEx.GetServiceProcessId(service.ServiceName)
                    };
                    killServ.RunTask(logExceptions);
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Stopped && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Could not kill dependent service.", ("Service", ServiceName));
                }
            } else if (Operation == ServiceOperation.Pause)
            {
                try
                {
                    service.Pause();
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Paused && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service pause failed.", ("Service", ServiceName));
                }

                try
                {
                    service.WaitForStatus(ServiceControllerStatus.Paused, TimeSpan.FromMilliseconds(5000));
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Paused && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service pause timeout exceeded.", ("Service", ServiceName));
                }
            }
            else if (Operation == ServiceOperation.Continue)
            {
                try
                {
                    service.Pause();
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service continue failed.", ("Service", ServiceName));
                }
                
                try
                {
                    service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(5000));
                }
                catch (Exception e)
                {
                    service.Refresh();
                    if (service.Status != ServiceControllerStatus.Running && logExceptions)
                        Log.EnqueueExceptionSafe(LogType.Warning, e, "Service continue timeout exceeded.", ("Service", ServiceName));
                }
            }

            service?.Dispose();
            Thread.Sleep(100);
            
            InProgress = false;
            return;
        }
    }
}
