using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Permissions;
using System.Text;
using Microsoft.Win32.SafeHandles;
using TrustedUninstaller.Shared;
using TrustedUninstaller.Shared.Actions;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.Shared
{
    public static class Win32
    {
        public static class Service
        {
            [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
            public static extern IntPtr CreateService(
                IntPtr hSCManager,
                string lpServiceName,
                string lpDisplayName,
                uint dwDesiredAccess,
                uint dwServiceType,
                uint dwStartType,
                uint dwErrorControl,
                string lpBinaryPathName,
                [Optional] string lpLoadOrderGroup,
                [Optional] string lpdwTagId,    // only string so we can pass null
                [Optional] string lpDependencies,
                [Optional] string lpServiceStartName,
                [Optional] string lpPassword);
            
            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DeleteService(IntPtr hService);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, SERVICE_ACCESS dwDesiredAccess);

            [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr OpenSCManager(string machineName, string databaseName, SCM_ACCESS dwDesiredAccess);
            
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool QueryServiceStatusEx(IntPtr Service, int InfoLevel,
                ref SERVICE_STATUS_PROCESS ServiceStatus, int BufSize, out int BytesNeeded);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseServiceHandle(IntPtr hSCObject);
            
            [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool EnumServicesStatusEx(
                IntPtr hSCManager,
                uint InfoLevel,
                SERVICE_TYPE dwServiceType,
                uint dwServiceState,
                IntPtr lpServices,
                int cbBufSize,
                out int pcbBytesNeeded,
                out int lpServicesReturned,
                ref int lpResumeHandle,
                string pszGroupName
            );
            
            public struct ENUM_SERVICE_STATUS_PROCESS {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string lpServiceName;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string lpDisplayName;
                public SERVICE_STATUS_PROCESS ServiceStatusProcess;
            }
            
            [StructLayout(LayoutKind.Sequential)]
            public struct SERVICE_STATUS_PROCESS
            {
                public SERVICE_TYPE ServiceType;
                public SERVICE_STATE CurrentState;
                public SERVICE_ACCEPT ControlsAccepted;
                public int Win32ExitCode;
                public int ServiceSpecificExitCode;
                public int CheckPoint;
                public int WaitHint;
                public int ProcessID;
                public SERVICE_FLAGS ServiceFlags;
            }
            
            public enum SERVICE_STATE : int
            {
                ContinuePending = 0x5,
                PausePending = 0x6,
                Paused = 0x7,
                Running = 0x4,
                StartPending = 0x2,
                StopPending = 0x3,
                Stopped = 0x1
            }
            
            public enum SERVICE_ACCEPT : int
            {
                NetBindChange = 0x10,
                ParamChange = 0x8,
                PauseContinue = 0x2,
                PreShutdown = 0x100,
                Shutdown = 0x4,
                Stop = 0x1,
                HardwareProfileChange = 0x20,
                PowerEvent = 0x40,
                SessionChange = 0x80
            }
            
            public enum SERVICE_FLAGS : int
            {
                None = 0,
                RunsInSystemProcess = 0x1
            }
            
            /// <summary>
            /// Service types.
            /// </summary>
            [Flags]
            public enum SERVICE_TYPE : uint
            {
                /// <summary>
                /// Driver service.
                /// </summary>
                SERVICE_KERNEL_DRIVER = 0x00000001,
                /// <summary>
                /// File system driver service.
                /// </summary>
                SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
                /// <summary>
                /// Service that runs in its own process.
                /// </summary>
                SERVICE_WIN32_OWN_PROCESS = 0x00000010,
                /// <summary>
                /// Service that shares a process with one or more other services.
                /// </summary>
                SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
                /// <summary>
                /// The service can interact with the desktop.
                /// </summary>
                SERVICE_INTERACTIVE_PROCESS = 0x00000100,
            }

            /// <summary>
            /// Service start options
            /// </summary>
            public enum SERVICE_START : uint
            {
                /// <summary>
                /// A device driver started by the system loader. This value is valid
                /// only for driver services.
                /// </summary>
                SERVICE_BOOT_START = 0x00000000,
                /// <summary>
                /// A device driver started by the IoInitSystem function. This value
                /// is valid only for driver services.
                /// </summary>
                SERVICE_SYSTEM_START = 0x00000001,
                /// <summary>
                /// A service started automatically by the service control manager
                /// during system startup. For more information, see Automatically
                /// Starting Services.
                /// </summary>        
                SERVICE_AUTO_START = 0x00000002,
                /// <summary>
                /// A service started by the service control manager when a process
                /// calls the StartService function. For more information, see
                /// Starting Services on Demand.
                /// </summary>
                SERVICE_DEMAND_START = 0x00000003,
                /// <summary>
                /// A service that cannot be started. Attempts to start the service
                /// result in the error code ERROR_SERVICE_DISABLED.
                /// </summary>
                SERVICE_DISABLED = 0x00000004,
            }

            /// <summary>
            /// Severity of the error, and action taken, if this service fails
            /// to start.
            /// </summary>
            public enum SERVICE_ERROR
            {
                /// <summary>
                /// The startup program ignores the error and continues the startup
                /// operation.
                /// </summary>
                SERVICE_ERROR_IGNORE = 0x00000000,
                /// <summary>
                /// The startup program logs the error in the event log but continues
                /// the startup operation.
                /// </summary>
                SERVICE_ERROR_NORMAL = 0x00000001,
                /// <summary>
                /// The startup program logs the error in the event log. If the
                /// last-known-good configuration is being started, the startup
                /// operation continues. Otherwise, the system is restarted with
                /// the last-known-good configuration.
                /// </summary>
                SERVICE_ERROR_SEVERE = 0x00000002,
                /// <summary>
                /// The startup program logs the error in the event log, if possible.
                /// If the last-known-good configuration is being started, the startup
                /// operation fails. Otherwise, the system is restarted with the
                /// last-known good configuration.
                /// </summary>
                SERVICE_ERROR_CRITICAL = 0x00000003,
            }

            [Flags]
            public enum SERVICE_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0xF0000,
                SERVICE_QUERY_CONFIG = 0x00001,
                SERVICE_CHANGE_CONFIG = 0x00002,
                SERVICE_QUERY_STATUS = 0x00004,
                SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
                SERVICE_START = 0x00010,
                SERVICE_STOP = 0x00020,
                SERVICE_PAUSE_CONTINUE = 0x00040,
                SERVICE_INTERROGATE = 0x00080,
                SERVICE_USER_DEFINED_CONTROL = 0x00100,
                SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP |
                    SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL)
            }

            [Flags]
            public enum SCM_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0xF0000,
                SC_MANAGER_CONNECT = 0x00001,
                SC_MANAGER_CREATE_SERVICE = 0x00002,
                SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
                SC_MANAGER_LOCK = 0x00008,
                SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
                SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,
                SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS |
                    SC_MANAGER_MODIFY_BOOT_CONFIG
            }
        }
        public static class ServiceEx {
            public static bool IsPendingDeleteOrDeleted(string serviceName)
            {
                var manager = Service.OpenSCManager(null, null, Service.SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
                if (manager == IntPtr.Zero)
                    return new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 }.GetStatus() == UninstallTaskStatus.Completed || 
                        new RegistryKeyAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Operation = RegistryKeyOperation.Delete }.GetStatus() == UninstallTaskStatus.Completed;

                var handle = Service.CreateService(manager, serviceName, "AME Deletion Check",
                    (uint)Service.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                    (uint)Service.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS, (uint)Service.SERVICE_START.SERVICE_DISABLED,
                    (uint)Service.SERVICE_ERROR.SERVICE_ERROR_IGNORE, @"ame-deletion-check");
                if (handle == IntPtr.Zero)
                {
                    if (Marshal.GetLastWin32Error() == 0x00000430)
                    {
                        return true;
                    }
                    return new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 }.GetStatus() == UninstallTaskStatus.Completed || 
                        new RegistryKeyAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Operation = RegistryKeyOperation.Delete }.GetStatus() == UninstallTaskStatus.Completed;
                }
                Service.DeleteService(handle);
                Service.CloseServiceHandle(handle);
                Service.CloseServiceHandle(manager);
                return true;
            }
            public static bool IsPendingStopOrStopped(string serviceName, out bool pending)
            {
                pending = false;
                var manager = Service.OpenSCManager(null, null, Service.SCM_ACCESS.SC_MANAGER_ENUMERATE_SERVICE);
                if (manager == IntPtr.Zero)
                    return false;

                var handle = Service.OpenService(manager, serviceName, 
                    Service.SERVICE_ACCESS.SERVICE_QUERY_STATUS);

                if (handle == IntPtr.Zero)
                    return true;
                
                Service.SERVICE_STATUS_PROCESS status = new Service.SERVICE_STATUS_PROCESS();
                
                if (!Service.QueryServiceStatusEx(handle, 0, ref status, Marshal.SizeOf(status), out int retLen))
                {
                    Service.CloseServiceHandle(handle);
                    Service.CloseServiceHandle(manager);
                    return false;
                }

                Service.CloseServiceHandle(handle);
                Service.CloseServiceHandle(manager);

                pending = status.CurrentState == Service.SERVICE_STATE.StopPending;
                return pending || status.CurrentState == Service.SERVICE_STATE.Stopped;
            }

            public static int GetServiceProcessId(string serviceName)
            {
                var manager = Service.OpenSCManager(null, null, Service.SCM_ACCESS.SC_MANAGER_ENUMERATE_SERVICE);
                if (manager == IntPtr.Zero)
                    throw new Exception("Error opening service manager.");

                var handle = Service.OpenService(manager, serviceName, 
                    Service.SERVICE_ACCESS.SERVICE_QUERY_STATUS);
                
                Service.SERVICE_STATUS_PROCESS status = new Service.SERVICE_STATUS_PROCESS();
                
                if (!Service.QueryServiceStatusEx(handle, 0, ref status, Marshal.SizeOf(status), out int retLen))
                {
                    Service.CloseServiceHandle(handle);
                    Service.CloseServiceHandle(manager);
                    throw new Exception("Error querying service ProcessId: " + Marshal.GetLastWin32Error());
                }
                Service.CloseServiceHandle(handle);
                Service.CloseServiceHandle(manager);
                
                return status.ProcessID == 0 ? -1 : status.ProcessID;
            }
            public static IEnumerable<string> GetServicesFromProcessId(int processId)
            {
                return GetServices(Service.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS |
                                   Service.SERVICE_TYPE.SERVICE_WIN32_SHARE_PROCESS).Where(x => x.ServiceStatusProcess.ProcessID == processId).Select(x => x.lpServiceName);
            }
            private static Service.ENUM_SERVICE_STATUS_PROCESS[] GetServices(Service.SERVICE_TYPE serviceTypes)
            {
                IntPtr handle = Service.OpenSCManager(null, null, Service.SCM_ACCESS.SC_MANAGER_ENUMERATE_SERVICE);
                if (handle == IntPtr.Zero)
                    throw new Exception("Could not open service manager.");
                
                int iBytesNeeded = 0;
                int iServicesReturned = 0;
                int iResumeHandle = 0;

                Service.EnumServicesStatusEx(handle,
                    0,
                    Service.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS | Service.SERVICE_TYPE.SERVICE_WIN32_SHARE_PROCESS,
                    1,
                    IntPtr.Zero,
                    0,
                    out iBytesNeeded,
                    out iServicesReturned,
                    ref iResumeHandle,
                    null);

                IntPtr buffer = Marshal.AllocHGlobal((int)iBytesNeeded);

                Service.EnumServicesStatusEx(handle,
                    0,
                    Service.SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS | Service.SERVICE_TYPE.SERVICE_WIN32_SHARE_PROCESS,
                    1,
                    buffer,
                    iBytesNeeded,
                    out iBytesNeeded,
                    out iServicesReturned,
                    ref iResumeHandle,
                    null);

                var services = new Service.ENUM_SERVICE_STATUS_PROCESS[iServicesReturned];
                var serviceSize = Marshal.SizeOf(typeof(Service.ENUM_SERVICE_STATUS_PROCESS));
                for (int i = 0; i < iServicesReturned; i++)
                {
                    var servicePtr = new IntPtr(buffer.ToInt64() + i * serviceSize);
                    services[i] = Marshal.PtrToStructure<Service.ENUM_SERVICE_STATUS_PROCESS>(servicePtr);
                }
                
                Marshal.FreeHGlobal(buffer);

                return services;
            }
        }
        
        public static class Tokens
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken(IntPtr hProcess, TokenAccessFlags DesiredAccess,
                out TokensEx.SafeTokenHandle hToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool GetTokenInformation(TokensEx.SafeTokenHandle TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength,
                out int ReturnLength);
            
            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetTokenInformation(
                TokensEx.SafeTokenHandle hToken,
                TOKEN_INFORMATION_CLASS tokenInfoClass,
                IntPtr pTokenInfo,
                int tokenInfoLength);
            
            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetTokenInformation(
                TokensEx.SafeTokenHandle hToken,
                TOKEN_INFORMATION_CLASS tokenInfoClass,
                ref uint pTokenInfo,
                int tokenInfoLength);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool DuplicateTokenEx(TokensEx.SafeTokenHandle hExistingToken, TokenAccessFlags dwDesiredAccess,
                IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType,
                out TokensEx.SafeTokenHandle phNewToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ImpersonateLoggedOnUser(TokensEx.SafeTokenHandle hToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue(IntPtr lpSystemName, string lpName, out LUID lpLuid);
            
            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern IntPtr RtlAdjustPrivilege(LUID privilege, bool bEnablePrivilege, bool isThreadPrivilege,
                out bool previousValue);

            [DllImport("ntdll.dll")]
            public static extern int ZwCreateToken(out TokensEx.SafeTokenHandle TokenHandle, TokenAccessFlags DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, ref LUID AuthenticationId,
                ref LARGE_INTEGER ExpirationTime, ref TOKEN_USER TokenUser, ref TOKEN_GROUPS TokenGroups,
                ref TOKEN_PRIVILEGES TokenPrivileges, ref TOKEN_OWNER TokenOwner,
                ref TOKEN_PRIMARY_GROUP TokenPrimaryGroup, ref TOKEN_DEFAULT_DACL TokenDefaultDacl,
                ref TOKEN_SOURCE TokenSource);

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_ATTRIBUTES : IDisposable
            {
                public int Length;
                public IntPtr RootDirectory;
                private IntPtr objectName;
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;

                public OBJECT_ATTRIBUTES(string name, uint attrs)
                {
                    Length = 0;
                    RootDirectory = IntPtr.Zero;
                    objectName = IntPtr.Zero;
                    Attributes = attrs;
                    SecurityDescriptor = IntPtr.Zero;
                    SecurityQualityOfService = IntPtr.Zero;
                    Length = Marshal.SizeOf(this);
                    ObjectName = new UNICODE_STRING(name);
                }

                public UNICODE_STRING ObjectName
                {
                    get => (UNICODE_STRING)Marshal.PtrToStructure(objectName, typeof(UNICODE_STRING));
                    set
                    {
                        var fDeleteOld = objectName != IntPtr.Zero;
                        if (!fDeleteOld) objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                        Marshal.StructureToPtr(value, objectName, fDeleteOld);
                    }
                }

                public void Dispose()
                {
                    if (objectName != IntPtr.Zero)
                    {
                        Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                        Marshal.FreeHGlobal(objectName);
                        objectName = IntPtr.Zero;
                    }
                }
            }

            [Flags]
            public enum TokenAccessFlags : uint
            {
                TOKEN_ADJUST_DEFAULT = 0x0080,
                TOKEN_ADJUST_GROUPS = 0x0040,
                TOKEN_ADJUST_PRIVILEGES = 0x0020,
                TOKEN_ADJUST_SESSIONID = 0x0100,
                TOKEN_ASSIGN_PRIMARY = 0x0001,
                TOKEN_DUPLICATE = 0x0002,
                TOKEN_EXECUTE = 0x00020000,
                TOKEN_IMPERSONATE = 0x0004,
                TOKEN_QUERY = 0x0008,
                TOKEN_QUERY_SOURCE = 0x0010,
                TOKEN_READ = 0x00020008,
                TOKEN_WRITE = 0x000200E0,
                TOKEN_ALL_ACCESS = 0x000F01FF,
                MAXIMUM_ALLOWED = 0x02000000
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum TOKEN_INFORMATION_CLASS
            {
                /// <summary>
                /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
                /// </summary>
                TokenUser = 1,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
                /// </summary>
                TokenGroups,

                /// <summary>
                /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
                /// </summary>
                TokenPrivileges,

                /// <summary>
                /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
                /// </summary>
                TokenOwner,

                /// <summary>
                /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
                /// </summary>
                TokenPrimaryGroup,

                /// <summary>
                /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
                /// </summary>
                TokenDefaultDacl,

                /// <summary>
                /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
                /// </summary>
                TokenSource,

                /// <summary>
                /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
                /// </summary>
                TokenType,

                /// <summary>
                /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
                /// </summary>
                TokenImpersonationLevel,

                /// <summary>
                /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
                /// </summary>
                TokenStatistics,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
                /// </summary>
                TokenRestrictedSids,

                /// <summary>
                /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
                /// </summary>
                TokenSessionId,

                /// <summary>
                /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
                /// </summary>
                TokenGroupsAndPrivileges,

                /// <summary>
                /// Reserved.
                /// </summary>
                TokenSessionReference,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
                /// </summary>
                TokenSandBoxInert,

                /// <summary>
                /// Reserved.
                /// </summary>
                TokenAuditPolicy,

                /// <summary>
                /// The buffer receives a TOKEN_ORIGIN value.
                /// </summary>
                TokenOrigin,

                /// <summary>
                /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
                /// </summary>
                TokenElevationType,

                /// <summary>
                /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
                /// </summary>
                TokenLinkedToken,

                /// <summary>
                /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
                /// </summary>
                TokenElevation,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
                /// </summary>
                TokenHasRestrictions,

                /// <summary>
                /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
                /// </summary>
                TokenAccessInformation,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
                /// </summary>
                TokenVirtualizationAllowed,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
                /// </summary>
                TokenVirtualizationEnabled,

                /// <summary>
                /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
                /// </summary>
                TokenIntegrityLevel,

                /// <summary>
                /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
                /// </summary>
                TokenUIAccess,

                /// <summary>
                /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
                /// </summary>
                TokenMandatoryPolicy,

                /// <summary>
                /// The buffer receives the token's logon security identifier (SID).
                /// </summary>
                TokenLogonSid,

                /// <summary>
                /// The maximum value for this enumeration
                /// </summary>
                MaxTokenInfoClass
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_GROUPS
            {
                public int GroupCount;

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
                public SID.SID_AND_ATTRIBUTES[] Groups;

                public TOKEN_GROUPS(int privilegeCount)
                {
                    GroupCount = privilegeCount;
                    Groups = new SID.SID_AND_ATTRIBUTES[32];
                }
            }

            public struct TOKEN_PRIMARY_GROUP
            {
                public IntPtr PrimaryGroup; // PSID

                public TOKEN_PRIMARY_GROUP(IntPtr _sid)
                {
                    PrimaryGroup = _sid;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_SOURCE
            {
                public TOKEN_SOURCE(string name)
                {
                    SourceName = new byte[8];
                    Encoding.GetEncoding(1252).GetBytes(name, 0, name.Length, SourceName, 0);
                    if (!SID.AllocateLocallyUniqueId(out SourceIdentifier)) throw new Win32Exception();
                }

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public byte[] SourceName;

                public LUID SourceIdentifier;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_USER
            {
                public SID.SID_AND_ATTRIBUTES User;

                public TOKEN_USER(IntPtr _sid)
                {
                    User = new SID.SID_AND_ATTRIBUTES { Sid = _sid, Attributes = 0 };
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_OWNER
            {
                public IntPtr Owner; // PSID

                public TOKEN_OWNER(IntPtr _owner)
                {
                    Owner = _owner;
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_DEFAULT_DACL
            {
                public IntPtr DefaultDacl; // PACL
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_PRIVILEGES
            {
                public int PrivilegeCount;

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
                public LUID_AND_ATTRIBUTES[] Privileges;

                public TOKEN_PRIVILEGES(int privilegeCount)
                {
                    PrivilegeCount = privilegeCount;
                    Privileges = new LUID_AND_ATTRIBUTES[36];
                }
            }

            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_QUALITY_OF_SERVICE
            {
                public int Length;
                public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public byte ContextTrackingMode;
                public byte EffectiveOnly;

                public SECURITY_QUALITY_OF_SERVICE(SECURITY_IMPERSONATION_LEVEL _impersonationLevel,
                    byte _contextTrackingMode, byte _effectiveOnly)
                {
                    Length = 0;
                    ImpersonationLevel = _impersonationLevel;
                    ContextTrackingMode = _contextTrackingMode;
                    EffectiveOnly = _effectiveOnly;
                    Length = Marshal.SizeOf(this);
                }
            }

            [Flags]
            public enum SE_PRIVILEGE_ATTRIBUTES : uint
            {
                SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
                SE_PRIVILEGE_ENABLED = 0x00000002,
                SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
            }

            [Flags]
            public enum SE_GROUP_ATTRIBUTES : uint
            {
                SE_GROUP_MANDATORY = 0x00000001,
                SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
                SE_GROUP_ENABLED = 0x00000004,
                SE_GROUP_OWNER = 0x00000008,
                SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
                SE_GROUP_INTEGRITY = 0x00000020,
                SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
                SE_GROUP_RESOURCE = 0x20000000,
                SE_GROUP_LOGON_ID = 0xC0000000,
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_MANDATORY_LABEL
            {
                public SID.SID_AND_ATTRIBUTES Label;
            }

            public const byte SECURITY_STATIC_TRACKING = 0;
            public static readonly LUID ANONYMOUS_LOGON_LUID = new LUID { LowPart = 0x3e6, HighPart = 0 };
            public static readonly LUID SYSTEM_LUID = new LUID { LowPart = 0x3e7, HighPart = 0 };
            public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";
            public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
            public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
            public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
            public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";
            public const string SE_TCB_NAME = "SeTcbPrivilege";
            public const string SE_SECURITY_NAME = "SeSecurityPrivilege";
            public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
            public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";
            public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";
            public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
            public const string SE_PROFILE_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";
            public const string SE_INCREASE_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";
            public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";
            public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";
            public const string SE_BACKUP_NAME = "SeBackupPrivilege";
            public const string SE_RESTORE_NAME = "SeRestorePrivilege";
            public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
            public const string SE_DEBUG_NAME = "SeDebugPrivilege";
            public const string SE_AUDIT_NAME = "SeAuditPrivilege";
            public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";
            public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";
            public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";
            public const string SE_UNDOCK_NAME = "SeUndockPrivilege";
            public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";
            public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";
            public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";
            public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
            public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";
            public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";
            public const string SE_RELABEL_NAME = "SeRelabelPrivilege";
            public const string SE_INCREASE_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";
            public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
            public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

            public const string SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME =
                "SeDelegateSessionUserImpersonatePrivilege";
        }

        public static class TokensEx
        {
            public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
            {
                // A default constructor is required for P/Invoke to instantiate the class
                public SafeTokenHandle(IntPtr preexistingHandle)
                    : base(ownsHandle: true)
                {
                    this.SetHandle(preexistingHandle);
                }
                public SafeTokenHandle()
                    : base(ownsHandle: true)
                {
                }
            
                protected override bool ReleaseHandle()
                {
                    return Win32.CloseHandle(handle);
                }
            }
            
            public static bool CreateTokenPrivileges(string[] privs, out Tokens.TOKEN_PRIVILEGES tokenPrivileges)
            {
                var sizeOfStruct = Marshal.SizeOf(typeof(Tokens.TOKEN_PRIVILEGES));
                var pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);
                tokenPrivileges = (Tokens.TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pPrivileges, typeof(Tokens.TOKEN_PRIVILEGES));
                tokenPrivileges.PrivilegeCount = privs.Length;
                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    if (!Win32.Tokens.LookupPrivilegeValue(IntPtr.Zero, privs[idx], out var luid)) return false;
                    tokenPrivileges.Privileges[idx].Attributes =
                        (uint)(Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                               Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                    tokenPrivileges.Privileges[idx].Luid = luid;
                }

                return true;
            }

            public static void AdjustCurrentPrivilege(string privilege)
            {
                Win32.Tokens.LookupPrivilegeValue(IntPtr.Zero, privilege, out LUID luid);
                Win32.Tokens.RtlAdjustPrivilege(luid, true, true, out _);
            }
            
            public static IntPtr GetInfoFromToken(SafeTokenHandle token, Win32.Tokens.TOKEN_INFORMATION_CLASS information)
            {
                Win32.Tokens.GetTokenInformation(token, information, IntPtr.Zero, 0, out int length);
                var result = Marshal.AllocHGlobal(length);
                Win32.Tokens.GetTokenInformation(token, information, result, length, out length);
                return result;
            }
        }

        public static class Process
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, TokensEx.SafeTokenHandle hToken, bool bInherit);
            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessAsUser(Win32.TokensEx.SafeTokenHandle hToken, string lpApplicationName, StringBuilder lpCommandLine, SECURITY_ATTRIBUTES lpProcessAttributes, SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);

            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CreateProcessWithToken(TokensEx.SafeTokenHandle hToken, LogonFlags dwLogonFlags,
                string lpApplicationName, string lpCommandLine, ProcessCreationFlags dwCreationFlags,
                IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            public enum LogonFlags
            {
                WithProfile = 1,
                NetCredentialsOnly
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }

            [Flags]
            public enum ProcessCreationFlags : uint
            {
                DEBUG_PROCESS = 0x00000001,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                CREATE_SUSPENDED = 0x00000004,
                DETACHED_PROCESS = 0x00000008,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                INHERIT_PARENT_AFFINITY = 0x00010000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NO_WINDOW = 0x08000000
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFO
            {
                public int cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public int dwX;
                public int dwY;
                public int dwXSize;
                public int dwYSize;
                public int dwXCountChars;
                public int dwYCountChars;
                public int dwFillAttribute;
                public int dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }
        }

        public static class IO
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr CreateFile([MarshalAs(UnmanagedType.LPTStr)] string filename,
                [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share,
                IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);

            [Flags]
            public enum FileAccess : uint
            {
                AccessSystemSecurity = 0x1000000,
                MaximumAllowed = 0x2000000,
                Delete = 0x10000,
                ReadControl = 0x20000,
                WriteDAC = 0x40000,
                WriteOwner = 0x80000,
                Synchronize = 0x100000,
                StandardRightsRequired = 0xF0000,
                StandardRightsRead = ReadControl,
                StandardRightsWrite = ReadControl,
                StandardRightsExecute = ReadControl,
                StandardRightsAll = 0x1F0000,
                SpecificRightsAll = 0xFFFF,
                FILE_READ_DATA = 0x0001, // file & pipe
                FILE_LIST_DIRECTORY = 0x0001, // directory
                FILE_WRITE_DATA = 0x0002, // file & pipe
                FILE_ADD_FILE = 0x0002, // directory
                FILE_APPEND_DATA = 0x0004, // file
                FILE_ADD_SUBDIRECTORY = 0x0004, // directory
                FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
                FILE_READ_EA = 0x0008, // file & directory
                FILE_WRITE_EA = 0x0010, // file & directory
                FILE_EXECUTE = 0x0020, // file
                FILE_TRAVERSE = 0x0020, // directory
                FILE_DELETE_CHILD = 0x0040, // directory
                FILE_READ_ATTRIBUTES = 0x0080, // all
                FILE_WRITE_ATTRIBUTES = 0x0100, // all

                //
                // Generic Section
                //
                GenericRead = 0x80000000,
                GenericWrite = 0x40000000,
                GenericExecute = 0x20000000,
                GenericAll = 0x10000000,
                SPECIFIC_RIGHTS_ALL = 0x00FFFF,
                FILE_ALL_ACCESS = StandardRightsRequired | Synchronize | 0x1FF,

                FILE_GENERIC_READ = StandardRightsRead | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA |
                                    Synchronize,

                FILE_GENERIC_WRITE = StandardRightsWrite | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                                     FILE_APPEND_DATA | Synchronize,
                FILE_GENERIC_EXECUTE = StandardRightsExecute | FILE_READ_ATTRIBUTES | FILE_EXECUTE | Synchronize
            }

            [Flags]
            public enum FileShare : uint
            {
                None = 0x00000000,
                Read = 0x00000001,
                Write = 0x00000002,
                Delete = 0x00000004
            }

            public enum FileMode : uint
            {
                New = 1,
                CreateAlways = 2,
                OpenExisting = 3,
                OpenAlways = 4,
                TruncateExisting = 5
            }

            [Flags]
            public enum FileAttributes : uint
            {
                Readonly = 0x00000001,
                Hidden = 0x00000002,
                System = 0x00000004,
                Directory = 0x00000010,
                Archive = 0x00000020,
                Device = 0x00000040,
                Normal = 0x00000080,
                Temporary = 0x00000100,
                SparseFile = 0x00000200,
                ReparsePoint = 0x00000400,
                Compressed = 0x00000800,
                Offline = 0x00001000,
                NotContentIndexed = 0x00002000,
                Encrypted = 0x00004000,
                Write_Through = 0x80000000,
                Overlapped = 0x40000000,
                NoBuffering = 0x20000000,
                RandomAccess = 0x10000000,
                SequentialScan = 0x08000000,
                DeleteOnClose = 0x04000000,
                BackupSemantics = 0x02000000,
                PosixSemantics = 0x01000000,
                OpenReparsePoint = 0x00200000,
                OpenNoRecall = 0x00100000,
                FirstPipeInstance = 0x00080000
            }
        }

        public static class SID
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AllocateAndInitializeSid(ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2,
                int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7,
                out IntPtr pSid);

            [DllImport("advapi32.dll")]
            public static extern bool AllocateLocallyUniqueId(out LUID allocated);

            [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr ptrSid);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetLengthSid(IntPtr pSid);
            
            [DllImport("advapi32.dll")]
            public static extern IntPtr FreeSid(IntPtr pSid);

            [StructLayout(LayoutKind.Sequential)]
            public struct SID_AND_ATTRIBUTES
            {
                public IntPtr Sid;
                public uint Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
                
                public SID_IDENTIFIER_AUTHORITY(byte[] value)
                {
                    this.Value = value;
                }
            }
            
            public enum SECURITY_MANDATORY_LABEL
            {
                Untrusted = 0x00000000,
                Low = 0x00001000,
                Medium = 0x00002000,
                MediumPlus = 0x00002100,
                High = 0x00003000,
                System = 0x00004000,
            }

            public static SID_IDENTIFIER_AUTHORITY SECURITY_MANDATORY_LABEL_AUTHORITY =
                new SID_IDENTIFIER_AUTHORITY(new byte[] { 0, 0, 0, 0, 0, 16 });
            public const int NtSecurityAuthority = 5;
            public const int AuthenticatedUser = 11;
            
            public const string DOMAIN_ALIAS_RID_ADMINS = "S-1-5-32-544";
            public const string DOMAIN_ALIAS_RID_LOCAL_AND_ADMIN_GROUP = "S-1-5-114";
            public const string TRUSTED_INSTALLER_RID =
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            
            public const string INTEGRITY_UNTRUSTED_SID = "S-1-16-0";
            public const string INTEGRITY_LOW_SID = "S-1-16-4096";
            public const string INTEGRITY_MEDIUM_SID = "S-1-16-8192";
            public const string INTEGRITY_MEDIUMPLUS_SID = "S-1-16-8448";
            public const string INTEGRITY_HIGH_SID = "S-1-16-12288";
            public const string INTEGRITY_SYSTEM_SID = "S-1-16-16384";
            public const string INTEGRITY_PROTECTEDPROCESS_SID = "S-1-16-20480";
        }

        public static class WTS
        {
            [DllImport("wtsapi32.dll", SetLastError = true)]
            public static extern int WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version,
                ref IntPtr ppSessionInfo, ref int pCount);

            [DllImport("wtsapi32.dll", SetLastError = true)]
            public static extern bool WTSEnumerateProcesses(IntPtr serverHandle, Int32 reserved, Int32 version,
                ref IntPtr ppProcessInfo, ref Int32 pCount);

            [DllImport("kernel32.dll")]
            public static extern uint WTSGetActiveConsoleSessionId();

            [DllImport("wtsapi32.dll", SetLastError = true)]
            public static extern bool WTSQueryUserToken(UInt32 sessionId, out TokensEx.SafeTokenHandle Token);

            [DllImport("wtsapi32.dll")]
            public static extern void WTSFreeMemory(IntPtr pMemory);

            [StructLayout(LayoutKind.Sequential)]
            public struct WTS_SESSION_INFO
            {
                public Int32 SessionID;
                [MarshalAs(UnmanagedType.LPStr)] 
                public String pWinStationName;
                public WTS_CONNECTSTATE_CLASS State;
            }

            public enum WTS_CONNECTSTATE_CLASS
            {
                WTSActive,
                WTSConnected,
                WTSConnectQuery,
                WTSShadow,
                WTSDisconnected,
                WTSIdle,
                WTSListen,
                WTSReset,
                WTSDown,
                WTSInit
            }

            public struct WTS_PROCESS_INFO
            {
                public int SessionID;
                public int ProcessID;
                public IntPtr ProcessName;
                public IntPtr UserSid;
            }
        }

        public static class LSA
        {
            [DllImport("secur32.dll", SetLastError = false)]
            public static extern uint LsaFreeReturnBuffer(IntPtr buffer);

            [DllImport("secur32.dll", SetLastError = false)]
            public static extern uint LsaEnumerateLogonSessions(out ulong LogonSessionCount,
                out IntPtr LogonSessionList);

            [DllImport("secur32.dll", SetLastError = false)]
            public static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

            [StructLayout(LayoutKind.Sequential)]
            public struct LSA_UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_LOGON_SESSION_DATA
            {
                public UInt32 Size;
                public LUID LoginID;
                public LSA_UNICODE_STRING Username;
                public LSA_UNICODE_STRING LoginDomain;
                public LSA_UNICODE_STRING AuthenticationPackage;
                public UInt32 LogonType;
                public UInt32 Session;
                public IntPtr PSiD;
                public UInt64 LoginTime;
                public LSA_UNICODE_STRING LogonServer;
                public LSA_UNICODE_STRING DnsDomainName;
                public LSA_UNICODE_STRING Upn;
            }

            public enum SECURITY_LOGON_TYPE : uint
            {
                Interactive = 2, //The security principal is logging on interactively.
                Network, //The security principal is logging using a network.
                Batch, //The logon is for a batch process.
                Service, //The logon is for a service account.
                Proxy, //Not supported.
                Unlock, //The logon is an attempt to unlock a workstation.
                NetworkCleartext, //The logon is a network logon with cleartext credentials.
                NewCredentials, // Allows the caller to clone its current token and specify new credentials for outbound connections.
                RemoteInteractive, // A terminal server session that is both remote and interactive.
                CachedInteractive, // Attempt to use the cached credentials without going out across the network.
                CachedRemoteInteractive, // Same as RemoteInteractive, except used publicly for auditing purposes.
                CachedUnlock // The logon is an attempt to unlock a workstation.
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SECURITY_ATTRIBUTES
        {
            public int nLength = 12;
            public SafeLocalMemHandle lpSecurityDescriptor = new SafeLocalMemHandle(IntPtr.Zero, false);
            public bool bInheritHandle;
        }
        
        [HostProtection(MayLeakOnAbort = true)]
        [SuppressUnmanagedCodeSecurityAttribute]
        public sealed class SafeLocalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            internal SafeLocalMemHandle(IntPtr existingHandle, bool ownsHandle) : base(ownsHandle)
            {
                SetHandle(existingHandle);
            }
            [DllImport("kernel32.dll")]
            [ResourceExposure(ResourceScope.None)]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            private static extern IntPtr LocalFree(IntPtr hMem);
            override protected bool ReleaseHandle()
            {
                return LocalFree(handle) == IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public int Low;
            [FieldOffset(4)] public int High;
            [FieldOffset(0)] public long QuadPart;

            public LARGE_INTEGER(long _quad)
            {
                Low = 0;
                High = 0;
                QuadPart = _quad;
            }

            public long ToInt64()
            {
                return ((long)High << 32) | (uint)Low;
            }

            public static LARGE_INTEGER FromInt64(long value)
            {
                return new LARGE_INTEGER { Low = (int)value, High = (int)(value >> 32) };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }
        
        public const int STATUS_SUCCESS = 0;
        public static readonly int STATUS_INFO_LENGTH_MISMATCH = Convert.ToInt32("0xC0000004", 16);
        public const int ERROR_BAD_LENGTH = 0x00000018;
        public const int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        public enum NtStatus : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,
            MaximumNtStatus = 0xffffffff
        }
    }
}