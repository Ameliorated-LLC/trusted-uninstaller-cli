using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Core;
using Microsoft.Win32.SafeHandles;
using TrustedUninstaller.Shared;

namespace TrustedUninstaller.Shared.Actions
{
    public enum Privilege
    {
        TrustedInstaller,
        System,
        CurrentUserTrustedInstaller,
        CurrentUserElevated,
        CurrentUser,
    }

    public class ProcessPrivilege
    {
        private static Win32.TokensEx.SafeTokenHandle userToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        private static Win32.TokensEx.SafeTokenHandle elevatedUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        private static Win32.TokensEx.SafeTokenHandle trustedInstallerUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        private static Win32.TokensEx.SafeTokenHandle systemToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        private static Win32.TokensEx.SafeTokenHandle impsersonatedSystemToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        private static Win32.TokensEx.SafeTokenHandle lsassToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);

        internal static void ResetTokens()
        {
            userToken.Dispose();
            elevatedUserToken.Dispose();
            trustedInstallerUserToken.Dispose();
            systemToken.Dispose();
            impsersonatedSystemToken.Dispose();
            lsassToken.Dispose();
            elevatedUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
            lsassToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
            trustedInstallerUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
            systemToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
            impsersonatedSystemToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
            userToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
        }

        private static readonly object _startLock = new object();

        public static void StartPrivilegedTask(AugmentedProcess.Process process, Privilege privilege)
        {
            lock (_startLock)
            {
                var tcs = StartThread(process, privilege);
                tcs.Task.Wait();
                for (int i = 0; tcs.Task.Result != null && i <= 3; i++)
                {
                    Log.EnqueueExceptionSafe(LogType.Warning, tcs.Task.Result, "Error launching privileged process.", ("ExePath", Path.GetFileName(process.StartInfo.FileName)));
                    ResetTokens();
                    Thread.Sleep(500 * i);
                    tcs = StartThread(process, privilege);
                    tcs.Task.Wait();
                }

                if (tcs.Task.Result != null)
                    throw new SecurityException("Error launching privileged process.", tcs.Task.Result);
            }
        }

        private static TaskCompletionSource<Exception> StartThread(AugmentedProcess.Process process, Privilege privilege)
        {
            var tcs = new TaskCompletionSource<Exception>();
            var thread = new Thread(() =>
            {
                try
                {
                    switch (privilege)
                    {
                        case (Privilege.System):
                            GetSystemToken();
                            process.Start(AugmentedProcess.Process.CreateType.UserToken, ref systemToken);
                            break;
                        case (Privilege.CurrentUser):
                            GetUserToken(true);
                            process.Start(AugmentedProcess.Process.CreateType.UserToken, ref userToken);
                            break;
                        case (Privilege.CurrentUserElevated):
                            GetElevatedUserToken(false);
                            process.Start(AugmentedProcess.Process.CreateType.UserToken, ref elevatedUserToken);
                            break;
                        case (Privilege.CurrentUserTrustedInstaller):
                            GetElevatedUserToken(true);
                            process.Start(AugmentedProcess.Process.CreateType.UserToken, ref trustedInstallerUserToken);
                            break;
                        default:
                            throw new ArgumentException("Unexpected.");
                    }
                }
                catch (Exception e)
                {
                    tcs.SetResult(e);
                    return;
                }

                tcs.SetResult(null);
            });
            thread.Start();
            return tcs;
        }

        private static uint GetUserSession()
        {
            var currentSessionId = (uint)Process.GetCurrentProcess().SessionId;

            uint sessionId = Wrap.ExecuteSafe(() =>
            {
                sessionId = Win32.WTS.WTSGetActiveConsoleSessionId();
                if (sessionId != 0xFFFFFFFF)
                {
                    bool success = Win32.WTS.WTSQuerySessionInformation(IntPtr.Zero, sessionId, Win32.WTS.WTS_INFO_CLASS.WTSConnectState,
                        out IntPtr buffer, out int returned);

                    if (success && Marshal.ReadInt32(buffer) == 0)
                        return sessionId;
                }
                return 0xFFFFFFFF;
            }, 0xFFFFFFFF).Value;
            if (sessionId != 0xFFFFFFFF && sessionId == currentSessionId)
                return sessionId;

            IntPtr pSessionInfo = IntPtr.Zero;
            Int32 count = 0;
            if (Win32.WTS.WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref pSessionInfo, ref count) == 0)
            {
                Log.EnqueueExceptionSafe(new Win32Exception(Marshal.GetLastWin32Error(), "Error enumerating user sessions."));
                return currentSessionId;
            }
            Int32 dataSize = Marshal.SizeOf(typeof(Win32.WTS.WTS_SESSION_INFO));
            Int64 current = (Int64)pSessionInfo;
            for (int i = 0; i < count; i++)
            {
                Win32.WTS.WTS_SESSION_INFO si =
                    (Win32.WTS.WTS_SESSION_INFO)Marshal.PtrToStructure((System.IntPtr)current,
                        typeof(Win32.WTS.WTS_SESSION_INFO));
                current += dataSize;
                if (si.State == Win32.WTS.WTS_CONNECTSTATE_CLASS.WTSActive)
                {
                    sessionId = (uint)si.SessionID;
                    if (sessionId == currentSessionId)
                        break;
                }
            }
            Win32.WTS.WTSFreeMemory(pSessionInfo);
            return sessionId;
        }

        private static void GetUserToken(bool getPrivileges)
        {
            if (getPrivileges)
            {
                GetSystemToken();
                var result = Win32.Tokens.ImpersonateLoggedOnUser(systemToken);
                if (!result)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Error impersonating system process token.");

                Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_ASSIGNPRIMARYTOKEN_NAME);
                Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_INCREASE_QUOTA_NAME);
            }

            if (!userToken.IsInvalid)
                return;

            var sessionId = GetUserSession();

            if (Win32.WTS.WTSQueryUserToken(sessionId, out Win32.TokensEx.SafeTokenHandle wtsToken))
            {
                if (!Win32.Tokens.DuplicateTokenEx(wtsToken, Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS,
                        IntPtr.Zero,
                        Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                        Win32.Tokens.TOKEN_TYPE.TokenPrimary, out userToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Failed to duplicate process token for lsass.");
                }
                return;
            }
            throw new Win32Exception("Error fetching active user session token: " + Marshal.GetLastWin32Error());
        }

        private static void GetElevatedUserToken(bool trustedInstaller)
        {
            GetSystemToken();
            var result = Win32.Tokens.ImpersonateLoggedOnUser(systemToken);

            if (!result)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Error impersonating system process token.");

            if (lsassToken.IsInvalid)
            {
                using var processHandle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, Process.GetProcessesByName("lsass").First().Id);
                if (!Win32.Tokens.OpenProcessToken(processHandle,
                        Win32.Tokens.TokenAccessFlags.TOKEN_DUPLICATE |
                        Win32.Tokens.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                        Win32.Tokens.TokenAccessFlags.TOKEN_QUERY | Win32.Tokens.TokenAccessFlags.TOKEN_IMPERSONATE,
                        out var tokenHandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token for lsass.");
                }

                if (!Win32.Tokens.DuplicateTokenEx(tokenHandle, Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS,
                        IntPtr.Zero,
                        Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        Win32.Tokens.TOKEN_TYPE.TokenImpersonation, out lsassToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Failed to duplicate process token for lsass.");
                }
            }

            result = Win32.Tokens.ImpersonateLoggedOnUser(lsassToken);
            if (!result)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Error impersonating lsass process token: " + Marshal.GetLastWin32Error());
            Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_ASSIGNPRIMARYTOKEN_NAME);
            Win32.TokensEx.AdjustCurrentPrivilege(Win32.Tokens.SE_INCREASE_QUOTA_NAME);

            if ((trustedInstaller ? !trustedInstallerUserToken.IsInvalid : !elevatedUserToken.IsInvalid))
                return;

            var privileges = new[]
            {
                Win32.Tokens.SE_INCREASE_QUOTA_NAME,
                Win32.Tokens.SE_MACHINE_ACCOUNT_NAME,
                Win32.Tokens.SE_SECURITY_NAME,
                Win32.Tokens.SE_TAKE_OWNERSHIP_NAME,
                Win32.Tokens.SE_LOAD_DRIVER_NAME,
                Win32.Tokens.SE_SYSTEM_PROFILE_NAME,
                Win32.Tokens.SE_SYSTEMTIME_NAME,
                Win32.Tokens.SE_PROFILE_SINGLE_PROCESS_NAME,
                Win32.Tokens.SE_INCREASE_BASE_PRIORITY_NAME,
                Win32.Tokens.SE_CREATE_PERMANENT_NAME,
                Win32.Tokens.SE_BACKUP_NAME,
                Win32.Tokens.SE_RESTORE_NAME,
                Win32.Tokens.SE_SHUTDOWN_NAME,
                Win32.Tokens.SE_DEBUG_NAME,
                Win32.Tokens.SE_AUDIT_NAME,
                Win32.Tokens.SE_SYSTEM_ENVIRONMENT_NAME,
                Win32.Tokens.SE_CHANGE_NOTIFY_NAME,
                Win32.Tokens.SE_UNDOCK_NAME,
                Win32.Tokens.SE_SYNC_AGENT_NAME,
                Win32.Tokens.SE_ENABLE_DELEGATION_NAME,
                Win32.Tokens.SE_MANAGE_VOLUME_NAME,
                Win32.Tokens.SE_IMPERSONATE_NAME,
                Win32.Tokens.SE_CREATE_GLOBAL_NAME,
                Win32.Tokens.SE_TRUSTED_CREDMAN_ACCESS_NAME,
                Win32.Tokens.SE_RELABEL_NAME,
                Win32.Tokens.SE_TIME_ZONE_NAME,
                Win32.Tokens.SE_CREATE_SYMBOLIC_LINK_NAME,
                Win32.Tokens.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
                Win32.Tokens.SE_ASSIGNPRIMARYTOKEN_NAME,
                Win32.Tokens.SE_REMOTE_SHUTDOWN_NAME,
                Win32.Tokens.SE_INCREASE_WORKING_SET_NAME,
                Win32.Tokens.SE_TCB_NAME,
                Win32.Tokens.SE_CREATE_PAGEFILE_NAME,
                Win32.Tokens.SE_LOCK_MEMORY_NAME,
                Win32.Tokens.SE_CREATE_TOKEN_NAME
            };
            var authId = Win32.Tokens.SYSTEM_LUID;

            GetUserToken(false);

            Win32.Tokens.DuplicateTokenEx(userToken,
                Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, IntPtr.Zero,
                Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, Win32.Tokens.TOKEN_TYPE.TokenPrimary,
                out Win32.TokensEx.SafeTokenHandle dupedUserToken);

            Win32.SID.AllocateAndInitializeSid(
                ref Win32.SID.SECURITY_MANDATORY_LABEL_AUTHORITY,
                1,
                trustedInstaller ? (int)Win32.SID.SECURITY_MANDATORY_LABEL.System : (int)Win32.SID.SECURITY_MANDATORY_LABEL.High,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                out Win32.SID.SafeSIDHandle integritySid);

            using (integritySid)
            {
                var tokenMandatoryLabel = new Win32.Tokens.TOKEN_MANDATORY_LABEL()
                {
                    Label = default(Win32.SID.SID_AND_ATTRIBUTES)
                };

                tokenMandatoryLabel.Label.Attributes = (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_INTEGRITY;
                tokenMandatoryLabel.Label.Sid = integritySid.DangerousGetHandle();

                var integritySize = Marshal.SizeOf(tokenMandatoryLabel);
                var tokenInfo = Marshal.AllocHGlobal(integritySize);

                Marshal.StructureToPtr(tokenMandatoryLabel, tokenInfo, false);

                Win32.Tokens.SetTokenInformation(
                    dupedUserToken,
                    Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                    tokenInfo,
                    integritySize + Win32.SID.GetLengthSid(integritySid));
            }

            var pTokenUser = Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenUser, Marshal.SizeOf<Win32.Tokens.TOKEN_USER>());
            var pTokenOwner =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenOwner, Marshal.SizeOf<Win32.Tokens.TOKEN_OWNER>());
            var pTokenPrivileges =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenPrivileges, Marshal.SizeOf<Win32.Tokens.TOKEN_PRIVILEGES>());
            var pTokenGroups =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenGroups, Marshal.SizeOf<Win32.Tokens.TOKEN_GROUPS>());
            var pTokenPrimaryGroup =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenPrimaryGroup, Marshal.SizeOf<Win32.Tokens.TOKEN_PRIMARY_GROUP>());
            var pTokenDefaultDacl =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenDefaultDacl, Marshal.SizeOf<Win32.Tokens.TOKEN_DEFAULT_DACL>());
            var pTokenSource =
                Win32.TokensEx.GetInfoFromToken(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSource, Marshal.SizeOf<Win32.Tokens.TOKEN_SOURCE>());

            var tokenUser =
                (Win32.Tokens.TOKEN_USER)Marshal.PtrToStructure(pTokenUser, typeof(Win32.Tokens.TOKEN_USER));

            var tokenPrivileges = trustedInstaller ? Win32.TokensEx.CreateTokenPrivileges(privileges) : Win32.TokensEx.CreateDefaultAdministratorTokenPrivileges();
            var tokenGroups = (Win32.Tokens.TOKEN_GROUPS)Marshal.PtrToStructure(
                pTokenGroups, typeof(Win32.Tokens.TOKEN_GROUPS));
            var tokenOwner =
                (Win32.Tokens.TOKEN_OWNER)Marshal.PtrToStructure(pTokenOwner, typeof(Win32.Tokens.TOKEN_OWNER));
            var tokenPrimaryGroup =
                (Win32.Tokens.TOKEN_PRIMARY_GROUP)Marshal.PtrToStructure(pTokenPrimaryGroup,
                    typeof(Win32.Tokens.TOKEN_PRIMARY_GROUP));
            var tokenDefaultDacl = (Win32.Tokens.TOKEN_DEFAULT_DACL)Marshal.PtrToStructure(
                pTokenDefaultDacl, typeof(Win32.Tokens.TOKEN_DEFAULT_DACL));
            var tokenSource = (Win32.Tokens.TOKEN_SOURCE)Marshal.PtrToStructure(
                pTokenSource, typeof(Win32.Tokens.TOKEN_SOURCE));

            /*
            for (var idx = 0; idx < tokenPrivileges.PrivilegeCount - 1; idx++)
            {
                if ((tokenPrivileges.Privileges[idx].Attributes &
                     (uint)Win32.Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED) != 0)
                {
                }

                if ((tokenPrivileges.Privileges[idx].Attributes &
                     (uint)Win32.Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0)
                {
                }
            }
            */

            Win32.SID.SafeSIDHandle adminsSid = null;
            Win32.SID.SafeSIDHandle localAndAdminSid = null;
            Win32.SID.SafeSIDHandle trustedInstallerSid = null;
            Win32.SID.SafeSIDHandle ntServiceSid = null;

            bool adminsFound = false;
            bool localAndAdminFound = false;

            for (var idx = 0; idx < tokenGroups.GroupCount - 1; idx++)
            {
                Win32.SID.ConvertSidToStringSid(tokenGroups.Groups[idx].Sid, out string strSid);
                if (string.Compare(strSid, Win32.SID.DOMAIN_ALIAS_RID_ADMINS, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    adminsFound = true;
                    tokenGroups.Groups[idx].Attributes = (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                                                         (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES
                                                             .SE_GROUP_ENABLED_BY_DEFAULT | (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY | (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_OWNER;
                }
                else if (string.Compare(strSid, Win32.SID.DOMAIN_ALIAS_RID_LOCAL_AND_ADMIN_GROUP, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    localAndAdminFound = true;
                    tokenGroups.Groups[idx].Attributes = (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                                                         (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES
                                                             .SE_GROUP_ENABLED_BY_DEFAULT | (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_MANDATORY;
                }
            }

            if (!adminsFound)
            {
                Win32.SID.ConvertStringSidToSid(Win32.SID.DOMAIN_ALIAS_RID_ADMINS, out adminsSid);
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = adminsSid.DangerousGetHandle();
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes =
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
                tokenGroups.GroupCount++;
            }
            if (!localAndAdminFound)
            {
                Win32.SID.ConvertStringSidToSid(Win32.SID.DOMAIN_ALIAS_RID_LOCAL_AND_ADMIN_GROUP, out localAndAdminSid);
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = localAndAdminSid.DangerousGetHandle();
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes =
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
                tokenGroups.GroupCount++;
            }

            if (trustedInstaller)
            {
                Win32.SID.ConvertStringSidToSid(Win32.SID.TRUSTED_INSTALLER_RID, out trustedInstallerSid);
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = trustedInstallerSid.DangerousGetHandle();
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes =
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
                tokenGroups.GroupCount++;

                Win32.SID.ConvertStringSidToSid(Win32.SID.NT_SERVICE_SID, out ntServiceSid);
                tokenGroups.Groups[tokenGroups.GroupCount].Sid = ntServiceSid.DangerousGetHandle();
                tokenGroups.Groups[tokenGroups.GroupCount].Attributes =
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED |
                    (uint)Win32.Tokens.SE_GROUP_ATTRIBUTES.SE_GROUP_ENABLED_BY_DEFAULT;
                tokenGroups.GroupCount++;
            }

            var expirationTime = new Win32.LARGE_INTEGER() { QuadPart = -1L };
            var sqos = new Win32.Tokens.SECURITY_QUALITY_OF_SERVICE(
                Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, Win32.Tokens.SECURITY_STATIC_TRACKING,
                0);
            var oa = new Win32.Tokens.OBJECT_ATTRIBUTES(string.Empty, 0) { };
            var pSqos = Marshal.AllocHGlobal(Marshal.SizeOf(sqos));
            Marshal.StructureToPtr(sqos, pSqos, true);
            oa.SecurityQualityOfService = pSqos;

            var status = trustedInstaller
                ? Win32.Tokens.ZwCreateToken(out trustedInstallerUserToken,
                    Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, ref oa, Win32.Tokens.TOKEN_TYPE.TokenPrimary,
                    ref authId, ref expirationTime, ref tokenUser, ref tokenGroups, ref tokenPrivileges, ref tokenOwner,
                    ref tokenPrimaryGroup, ref tokenDefaultDacl, ref tokenSource)
                : Win32.Tokens.ZwCreateToken(out elevatedUserToken,
                    Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, ref oa, Win32.Tokens.TOKEN_TYPE.TokenPrimary,
                    ref authId, ref expirationTime, ref tokenUser, ref tokenGroups, ref tokenPrivileges, ref tokenOwner,
                    ref tokenPrimaryGroup, ref tokenDefaultDacl, ref tokenSource);

            Win32.LocalFree(pTokenUser);
            Win32.LocalFree(pTokenOwner);
            Win32.LocalFree(pTokenGroups);
            Win32.LocalFree(pTokenDefaultDacl);
            Win32.LocalFree(pTokenPrivileges);
            Win32.LocalFree(pTokenPrimaryGroup);

            adminsSid?.Dispose();
            localAndAdminSid?.Dispose();
            trustedInstallerSid?.Dispose();
            ntServiceSid?.Dispose();

            if (status != 0)
                throw new Win32Exception($"Error creating {(trustedInstaller ? "trusted installer" : "elevated")} user token: " + status);

            Win32.Tokens.GetTokenInformation(dupedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSessionId, out int sessionId, sizeof(int), out _);
            if (!Win32.Tokens.SetTokenInformation(trustedInstaller ? trustedInstallerUserToken : elevatedUserToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(int)))
            {
                if (trustedInstaller)
                {
                    trustedInstallerUserToken.Dispose();
                    trustedInstallerUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
                }
                else
                {
                    elevatedUserToken.Dispose();
                    elevatedUserToken = new Win32.TokensEx.SafeTokenHandle(IntPtr.Zero);
                }
                throw new Win32Exception("Error setting token session id: " + Marshal.GetLastWin32Error());
            }
        }

        public static void GetSystemToken()
        {
            if (!systemToken.IsInvalid)
                return;

            try
            {
                using var processHandle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, Process.GetProcessesByName("winlogon").First().Id);
                if (!Win32.Tokens.OpenProcessToken(processHandle,
                        Win32.Tokens.TokenAccessFlags.TOKEN_DUPLICATE | Win32.Tokens.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                        Win32.Tokens.TokenAccessFlags.TOKEN_QUERY | Win32.Tokens.TokenAccessFlags.TOKEN_IMPERSONATE,
                        out var tokenHandle))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token for winlogon.");
                }

                if (!Win32.Tokens.DuplicateTokenEx(tokenHandle, Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, IntPtr.Zero,
                        Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                        Win32.Tokens.TOKEN_TYPE.TokenPrimary, out systemToken))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Failed to duplicate process token for winlogon.");
                }

                using var currentProcess = Process.GetCurrentProcess();
                Win32.Tokens.OpenProcessToken(new SafeProcessHandle(currentProcess.Handle, false), Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, out Win32.TokensEx.SafeTokenHandle currentHandle);
                Win32.Tokens.GetTokenInformation(currentHandle, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSessionId, out int sessionId, sizeof(int), out _);
                if (!Win32.Tokens.SetTokenInformation(systemToken, Win32.Tokens.TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(int)))
                {
                    systemToken = null;
                    throw new Win32Exception("Error setting token session id: " + Marshal.GetLastWin32Error());
                }
            }
            catch (Exception e)
            {
                var sessionId = GetUserSession();
                int dwLsassPID = -1;
                int dwWinLogonPID = -1;
                Win32.WTS.WTS_PROCESS_INFO[] pProcesses;
                IntPtr pProcessInfo = IntPtr.Zero;
                int dwProcessCount = 0;
                if (Win32.WTS.WTSEnumerateProcesses((IntPtr)null, 0, 1, ref pProcessInfo, ref dwProcessCount))
                {
                    IntPtr pMemory = pProcessInfo;
                    pProcesses = new Win32.WTS.WTS_PROCESS_INFO[dwProcessCount];
                    for (int i = 0; i < dwProcessCount; i++)
                    {
                        pProcesses[i] =
                            (Win32.WTS.WTS_PROCESS_INFO)Marshal.PtrToStructure(pProcessInfo,
                                typeof(Win32.WTS.WTS_PROCESS_INFO));
                        pProcessInfo = (IntPtr)((long)pProcessInfo + Marshal.SizeOf(pProcesses[i]));
                        var processName = Marshal.PtrToStringAnsi(pProcesses[i].ProcessName);
                        Win32.SID.ConvertSidToStringSid(pProcesses[i].UserSid, out string sid);
                        string strSid;
                        if (processName == null || pProcesses[i].UserSid == default || sid != "S-1-5-18") continue;
                        if ((-1 == dwLsassPID) && (0 == pProcesses[i].SessionID) && (processName == "lsass.exe"))
                        {
                            dwLsassPID = pProcesses[i].ProcessID;
                            continue;
                        }

                        if ((-1 == dwWinLogonPID) && (sessionId == pProcesses[i].SessionID) &&
                            (processName == "winlogon.exe"))
                        {
                            dwWinLogonPID = pProcesses[i].ProcessID;
                            continue;
                        }
                    }

                    Win32.WTS.WTSFreeMemory(pMemory);
                }

                SafeProcessHandle systemProcessHandle;
                try
                {
                    systemProcessHandle = new SafeProcessHandle(Process.GetProcessById(dwLsassPID).Handle, false);
                }
                catch
                {
                    systemProcessHandle = new SafeProcessHandle(Process.GetProcessById(dwWinLogonPID).Handle, false);
                }

                if (!Win32.Tokens.OpenProcessToken(systemProcessHandle, Win32.Tokens.TokenAccessFlags.TOKEN_DUPLICATE,
                        out Win32.TokensEx.SafeTokenHandle token))
                {
                    systemProcessHandle.Dispose();
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token.");
                }

                if (!Win32.Tokens.DuplicateTokenEx(token, Win32.Tokens.TokenAccessFlags.MAXIMUM_ALLOWED, IntPtr.Zero,
                        Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                        Win32.Tokens.TOKEN_TYPE.TokenPrimary, out systemToken))
                {
                    systemProcessHandle.Dispose();
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to duplicate process token.");
                }
            }
        }

        public static Win32.TokensEx.SafeTokenHandle GetCurrentProcessToken()
        {
            if (!Win32.Tokens.OpenProcessToken(Win32.Process.GetCurrentProcess(),
                    Win32.Tokens.TokenAccessFlags.TOKEN_READ, out Win32.TokensEx.SafeTokenHandle token))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Error opening token for current process.");
            return token;
        }

        private static Win32.TokensEx.SafeTokenHandle GetProcessTokenByName(string name, bool impersonation)
        {
            var processHandle = new SafeProcessHandle(Process.GetProcessesByName(name).First().Handle, false);
            if (!Win32.Tokens.OpenProcessToken(processHandle,
                    Win32.Tokens.TokenAccessFlags.TOKEN_DUPLICATE | Win32.Tokens.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY |
                    Win32.Tokens.TokenAccessFlags.TOKEN_QUERY | Win32.Tokens.TokenAccessFlags.TOKEN_IMPERSONATE,
                    out var tokenHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open process token for " + name + ".");
            }

            if (!Win32.Tokens.DuplicateTokenEx(tokenHandle, Win32.Tokens.TokenAccessFlags.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    impersonation ? Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation : Win32.Tokens.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    impersonation ? Win32.Tokens.TOKEN_TYPE.TokenImpersonation : Win32.Tokens.TOKEN_TYPE.TokenPrimary, out Win32.TokensEx.SafeTokenHandle handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "Failed to duplicate process token for " + name + ".");
            }
            return handle;
        }
    }
}