using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Xml.Serialization;
using Core;
using Interprocess;
using Microsoft.Win32;
using TrustedUninstaller.Shared;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;
using WUApiLib;

namespace TrustedUninstaller.Shared
{
    public static class Requirements
    {
        [Serializable]
        public enum Requirement
        {
            [XmlEnum("Internet")]
            Internet = 0,
            [XmlEnum("NoInternet")]
            NoInternet = 1,
            [XmlEnum("DefenderDisabled")]
            DefenderDisabled = 2,
            [XmlEnum("DefenderToggled")]
            DefenderToggled = 3,
            [XmlEnum("NoPendingUpdates")]
            NoPendingUpdates = 4,
            [XmlEnum("Activation")]
            Activation = 5,
            [XmlEnum("NoAntivirus")]
            NoAntivirus = 6,
            [XmlEnum("LocalAccounts")]
            LocalAccounts = 11,
            [XmlEnum("PasswordSet")]
            PasswordSet = 11,
            [XmlEnum("AdministratorPasswordSet")]
            AdministratorPasswordSet = 8,
            [XmlEnum("PluggedIn")]
            PluggedIn = 9,
            [XmlEnum("NoTweakware")]
            NoTweakware = 10,
        }

        public static async Task<Requirement[]> MetRequirements(this Requirement[] requirements, bool checkNoPendingUpdate = false)
        {
            var requirementEnum = (Requirement[])Enum.GetValues(typeof(Requirement));
            if (requirements == null)
            {
                return requirementEnum;
            }
            // Add all requirements that are not included
            var metRequirements = requirementEnum.Except(requirements).ToList();

            if (requirements.Contains(Requirement.Internet))
                if (await new Internet().IsMet()) metRequirements.Add(Requirement.Internet);
                else metRequirements.Add(Requirement.NoInternet);

            if (requirements.Contains(Requirement.NoAntivirus))
                if (true) metRequirements.Add(Requirement.NoAntivirus);

            // Handled upstream
            if (requirements.Contains(Requirement.Activation))
                if (true) metRequirements.Add(Requirement.Activation);
            
            if (requirements.Contains(Requirement.DefenderDisabled))
                if (await new DefenderDisabled().IsMet()) metRequirements.Add(Requirement.DefenderDisabled);
            
            if (requirements.Contains(Requirement.PluggedIn))
                if (await new Battery().IsMet()) metRequirements.Add(Requirement.PluggedIn);
            
            if (requirements.Contains(Requirement.NoPendingUpdates))
                if (!checkNoPendingUpdate || (new [] {
                        Requirement.Internet,
                        Requirement.NoInternet,
                        Requirement.PluggedIn,
                        Requirement.DefenderDisabled
                    }.All(metRequirements.Contains) &&
                    await new NoPendingUpdates().IsMet())) metRequirements.Add(Requirement.NoPendingUpdates);

            if (requirements.Contains(Requirement.DefenderToggled))
                if (await new DefenderDisabled().IsMet()) metRequirements.Add(Requirement.DefenderToggled);

            if (requirements.Contains(Requirement.LocalAccounts))
                metRequirements.Add(Requirement.LocalAccounts);

            if (requirements.Contains(Requirement.AdministratorPasswordSet))
                metRequirements.Add(Requirement.AdministratorPasswordSet);
            
            return metRequirements.ToArray();
        }
        
        public interface IRequirements
        {
            Task<bool> IsMet();
            Task<bool> Meet();
        }
        public class RequirementBase
        {
            public class ProgressEventArgs : EventArgs
            {
                public int PercentAdded;
                public ProgressEventArgs(int percent)
                {
                    PercentAdded = percent;
                }
            }
            
            public event EventHandler<ProgressEventArgs> ProgressChanged;

            protected void OnProgressAdded(int percent)
            {
                ProgressChanged?.Invoke(this, new ProgressEventArgs(percent));
            }
        }

        public class Battery : RequirementBase, IRequirements
        {
            [StructLayout(LayoutKind.Sequential)]
            public class PowerState
            {
                public ACLineStatus ACLineStatus;
                public BatteryFlag BatteryFlag;
                public Byte BatteryLifePercent;
                public Byte Reserved1;
                public Int32 BatteryLifeTime;
                public Int32 BatteryFullLifeTime;

                // direct instantation not intended, use GetPowerState.
                private PowerState() {}

                public static PowerState GetPowerState()
                {
                    PowerState state = new PowerState();
                    if (GetSystemPowerStatusRef(state))
                        return state;

                    throw new ApplicationException("Unable to get power state");
                }

                [DllImport("Kernel32", EntryPoint = "GetSystemPowerStatus")]
                private static extern bool GetSystemPowerStatusRef(PowerState sps);
            }

            // Note: Underlying type of byte to match Win32 header
            public enum ACLineStatus : byte
            {
                Offline = 0, Online = 1, Unknown = 255
            }

            public enum BatteryFlag : byte
            {
                High = 1, Low = 2, Critical = 4, Charging = 8,
                NoSystemBattery = 128, Unknown = 255
            }

            public async Task<bool> IsMet()
            {
                try
                {
                    PowerState state = PowerState.GetPowerState();
                    if ((state.BatteryFlag == BatteryFlag.NoSystemBattery || state.BatteryFlag == BatteryFlag.Charging)
                        || state.ACLineStatus == ACLineStatus.Online || (state.ACLineStatus == ACLineStatus.Unknown && state.BatteryFlag == BatteryFlag.Unknown))
                        return true;
                    else
                        return false;
                }
                catch { }
                return true;
            }

            public Task<bool> Meet() => throw new NotImplementedException();
        }

        public class Internet : RequirementBase, IRequirements
        {
            [DllImport("wininet.dll", SetLastError = true)]
            private static extern bool InternetCheckConnection(string lpszUrl, int dwFlags, int dwReserved);
            
            [DllImport("wininet.dll", SetLastError=true)]
            extern static bool InternetGetConnectedState(out int lpdwFlags, int dwReserved);
            
            public async Task<bool> IsMet()
            {
                try
                {
                    try
                    {
                        if (!InternetCheckConnection("http://archlinux.org", 1, 0))
                        {
                            if (!InternetCheckConnection("http://google.com", 1, 0))
                                return false;
                        }
                        return true;
                    }
                    catch
                    {
                        var request = (HttpWebRequest)WebRequest.Create("http://google.com");
                        request.KeepAlive = false;
                        request.Timeout = 5000;
                        using (var response = (HttpWebResponse)request.GetResponse())
                            return true;
                    }
                }
                catch
                {
                    return false;
                }
            }

            public Task<bool> Meet() => throw new NotImplementedException();
        }

        public class DefenderDisabled : RequirementBase, IRequirements
        {
            public async Task<bool> IsMet()
            {
                return !Process.GetProcessesByName("MsMpEng").Any() && !Process.GetProcessesByName("SecurityHealthService").Any() && !Process.GetProcessesByName("MpDefenderCoreService").Any();
            }

            public async Task<bool> Meet() => throw new NotImplementedException();
        }
        
        public class DefenderToggled : RequirementBase, IRequirements
        {
            public async Task<bool> IsMet()
            {
                var defenderKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender");

                RegistryKey realtimeKey = null;
                try
                {
                    realtimeKey = defenderKey.OpenSubKey("Real-Time Protection");
                }
                catch
                {
                    
                }
                if (realtimeKey != null)
                {
                    try
                    {
                        if (!((int)realtimeKey.GetValue("DisableRealtimeMonitoring") != 1))
                            return false;
                    }
                    catch (Exception exception)
                    {
                        return false;
                    }
                }

                try
                {
                    if (!((int)defenderKey.OpenSubKey("SpyNet").GetValue("SpyNetReporting") != 0))
                            return false;
                }
                catch
                {

                }
                try
                {
                    if (!((int)defenderKey.OpenSubKey("SpyNet").GetValue("SubmitSamplesConsent") != 0))
                            return false;
                }
                catch
                {

                }
                try
                {
                    if (!((int)defenderKey.OpenSubKey("Features").GetValue("TamperProtection") != 4))
                            return false;
                }
                catch
                {

                }
                return true;
            }

            public async Task<bool> Meet()
            {
                throw new NotImplementedException();
            }
        }
        
        class SearchCompletedCallback : ISearchCompletedCallback
        {
            public void Invoke(ISearchJob searchJob, ISearchCompletedCallbackArgs callbackArgs)
            {
                this.CompleteTask();
            }
            
            private TaskCompletionSource<bool> taskSource = new TaskCompletionSource<bool>();
            protected void CompleteTask()
            {
                taskSource.SetResult(true);
            }

            public Task Task
            {
                get
                {
                    return taskSource.Task;
                }
            }
        }

        public class NoPendingUpdates : RequirementBase, IRequirements
        {
            public async Task<bool> IsMet()
            {
                // Using WUApiLib can crash the entire application if
                // Windows Update is faulty. For that reason we use a
                // separate process. To replicate, use an ameliorated
                // system and copy wuapi.dll & wuaeng.dll to System32.
                var result = await InterLink.ExecuteDisposableSafeAsync(TargetLevel.User, () => CheckDisposable(), logExceptions: true);
                if (result.Failed)
                    return true;

                return result.Value;
            }

            public Task<bool> Meet() => throw new NotImplementedException();
            
            [InterprocessMethod(Level.User)]
            private static bool CheckDisposable()
            {
                try
                {
                    var updateSession = new UpdateSession();
                    var updateSearcher = updateSession.CreateUpdateSearcher();
                    updateSearcher.Online = false; //set to true if you want to search online

                    SearchCompletedCallback searchCompletedCallback = new SearchCompletedCallback();

                    ISearchJob searchJob = updateSearcher.BeginSearch("IsInstalled=0 And IsHidden=0 And Type='Software' And DeploymentAction=*", searchCompletedCallback, null);

                    try
                    {
                        searchCompletedCallback.Task.Wait(50000);
                    }
                    catch (OperationCanceledException)
                    {
                        searchJob.RequestAbort();
                    }

                    ISearchResult searchResult = updateSearcher.EndSearch(searchJob);

                    if (searchResult.Updates.Cast<IUpdate>().Any(x => x.IsDownloaded))
                    {
                        return false;
                    }
                }
                catch (Exception e)
                {
                    Log.EnqueueExceptionSafe(e);
                    return true;
                }
                return true;
            }
        }
        
        public class NoAntivirus : RequirementBase, IRequirements
        {
            public async Task<bool> IsMet()
            {
                return !WinUtil.GetEnabledAvList(false).Any();
            }

            public Task<bool> Meet() => throw new NotImplementedException();
        }

        public class Activation : RequirementBase, IRequirements
        {
            public async Task<bool> IsMet()
            {
                return WinUtil.IsGenuineWindows();
            }

            public Task<bool> Meet() => throw new NotImplementedException();
        }
        
        public class WindowsBuild
        {
            public bool IsMet(string[] builds)
            {
                return builds.Any(x => x.Equals(Win32.SystemInfoEx.WindowsVersion.BuildNumber.ToString()));
            }

            public Task<bool> Meet() => throw new NotImplementedException();
        }
        
    }
}
