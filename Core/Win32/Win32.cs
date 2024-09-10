using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Permissions;
using System.Text;
using System.Windows;
using JetBrains.Annotations;
using Microsoft.Win32.SafeHandles;
using Core.Actions;
using Microsoft.Win32;

namespace Core
{
    public static class Win32
    {
        public static class SystemInfo
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            public class MEMORYSTATUSEX
            {
                public uint dwLength;
                public uint dwMemoryLoad;
                public ulong ullTotalPhys;
                public ulong ullAvailPhys;
                public ulong ullTotalPageFile;
                public ulong ullAvailPageFile;
                public ulong ullTotalVirtual;
                public ulong ullAvailVirtual;
                public ulong ullAvailExtendedVirtual;
                public MEMORYSTATUSEX()
                {
                    this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
                }
            }

            [return: MarshalAs(UnmanagedType.Bool)]
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);
            
            [StructLayout(LayoutKind.Sequential)]
            public struct RTL_OSVERSIONINFOEX
            {
                internal uint dwOSVersionInfoSize;
                internal uint dwMajorVersion;
                internal uint dwMinorVersion;
                internal uint dwBuildNumber;
                internal uint dwPlatformId;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
                internal string szCSDVersion;
            }
            [DllImport("ntdll")]
            public static extern int RtlGetVersion(ref RTL_OSVERSIONINFOEX lpVersionInformation);

            public enum MachineType : ushort
            {
                IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
                IMAGE_FILE_MACHINE_ALPHA = 0x184, //Digital Equipment Corporation (DEC) Alpha (32-bit)
                IMAGE_FILE_MACHINE_AM33 = 0x1d3, //Matsushita AM33, now MN103 (32-bit) part of Panasonic Corporation
                IMAGE_FILE_MACHINE_AMD64 =
                    0x8664, //AMD (64-bit) - was Advanced Micro Devices, now means x64  - OVERLOADED _AMD64 = 0x8664 - http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx  
                IMAGE_FILE_MACHINE_ARM = 0x1c0, //ARM little endian (32-bit), ARM Holdings, later versions 6+ used in iPhone, Microsoft Nokia N900
                IMAGE_FILE_MACHINE_ARMV7 = 0x1c4, //ARMv7 or IMAGE_FILE_MACHINE_ARMNT (or higher) Thumb mode only (32 bit).
                IMAGE_FILE_MACHINE_ARM64 = 0xaa64, //ARM8+ (64-bit)
                IMAGE_FILE_MACHINE_EBC = 0xebc, //EFI byte code (32-bit), now (U)EFI or (Unified) Extensible Firmware Interface
                IMAGE_FILE_MACHINE_I386 = 0x14c, //Intel 386 or later processors and compatible processors (32-bit)
                IMAGE_FILE_MACHINE_I860 = 0x14d, //Intel i860 (aka 80860) (32-bit) was a RISC microprocessor design introduced by Intel in 1989, this was depricated in 90's
                IMAGE_FILE_MACHINE_IA64 = 0x200, //Intel Itanium architecture processor family, (64-bit)
                IMAGE_FILE_MACHINE_M68K = 0x268, //Motorola 68000 Series (32-bit) CISC microprocessors
                IMAGE_FILE_MACHINE_M32R = 0x9041, //Mitsubishi M32R little endian (32-bit) now owned by Renesas Electronics Corporation
                IMAGE_FILE_MACHINE_MIPS16 = 0x266, //MIPS16 (16-bit instruction codes, 8to32bit bus)- Microprocessor without Interlocked Pipeline Stages Architecture
                IMAGE_FILE_MACHINE_MIPSFPU = 0x366, //MIPS with FPU, MIPS Technologies (32-bit)
                IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466, //MIPS16 with FPU (Floating Point Unit aka a math co-processesor)(16-bit instruction codes, 8to32bit bus)
                IMAGE_FILE_MACHINE_POWERPC = 0x1f0, //Power PC little endian, Performance Optimization With Enhanced RISC – Performance Computing (32-bit) one of the first
                IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1, //Power PC with floating point support (FPU) (32-bit), designed by AIM Alliance (Apple, IBM, and Motorola)
                IMAGE_FILE_MACHINE_POWERPCBE = 0x01F2, //Power PC Big Endian (64?-bits)
                IMAGE_FILE_MACHINE_R3000 = 0x0162, //R3000 (32-bit) RISC processor
                IMAGE_FILE_MACHINE_R4000 = 0x166, //R4000 MIPS (64-bit) - claims to be first true 64-bit processor
                IMAGE_FILE_MACHINE_R10000 =
                    0x0168, //R10000 MIPS IV is a (64-bit) architecture, but the R10000 did not implement the entire physical or virtual address to reduce cost. Instead, it has a 40-bit physical address and a 44-bit virtual address, thus it is capable of addressing 1 TB of physical memory and 16 TB of virtual memory. These comments by metadataconsulting.ca
                IMAGE_FILE_MACHINE_SH3 = 0x1a2, //Hitachi SH-3 (32-bit) - SuperH processor (SH3) core family
                IMAGE_FILE_MACHINE_SH3DSP = 0x1a3, //Hitachi SH-3 DSP (32-bit)
                IMAGE_FILE_MACHINE_SH4 = 0x1a6, //Hitachi SH-4 (32-bit)
                IMAGE_FILE_MACHINE_SH5 = 0x1a8, //Hitachi SH-5, (64-bit) core with a 128-bit vector FPU (64 32-bit registers) and an integer unit which includes the SIMD support and 63 64-bit registers.
                IMAGE_FILE_MACHINE_TRICORE = 0x0520, //Infineon AUDO (Automotive unified processor) (32-bit) - Tricore architecture a unified RISC/MCU/DSP microcontroller core
                IMAGE_FILE_MACHINE_THUMB = 0x1c2, //ARM or Thumb (interworking), (32-bit) core instruction set, used in Nintendo Gameboy Advance
                IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169, //MIPS Windows Compact Edition v2
                IMAGE_FILE_MACHINE_ALPHA64 = 0x284 //DEC Alpha AXP (64-bit) or IMAGE_FILE_MACHINE_AXP64
            }
            
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool IsWow64Process2(
                IntPtr process,
                out MachineType processMachine,
                out MachineType nativeMachine
            );
        }

        public static class SystemInfoEx
        {
            private static WindowsVersionInfo? _windowsVersion;
            public static WindowsVersionInfo WindowsVersion => _windowsVersion ??= RtlGetVersion();

            private static ulong? _systemMemory;
            public static ulong SystemMemory => _systemMemory ??= GetSystemMemoryInBytes();
            
            private static Architecture? _systemArchitecture;
            public static Architecture SystemArchitecture => _systemArchitecture ??= GetArchitecture();
            
            public static ulong GetSystemMemoryInBytes()
            {
                SystemInfo.MEMORYSTATUSEX memStatus = new SystemInfo.MEMORYSTATUSEX();
                if (SystemInfo.GlobalMemoryStatusEx(memStatus))
                    return memStatus.ullTotalPhys;
                else
                    return 0;
            }

            public static Architecture GetArchitecture()
            {
                SystemInfo.MachineType processType = SystemInfo.MachineType.IMAGE_FILE_MACHINE_UNKNOWN;
                SystemInfo.MachineType hostType = SystemInfo.MachineType.IMAGE_FILE_MACHINE_UNKNOWN;
                SystemInfo.IsWow64Process2(Win32.Process.GetCurrentProcess().DangerousGetHandle(), out processType, out hostType);

                switch (hostType)
                {
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_ARMV7:
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_ARM:
                        return Architecture.Arm;
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_ARM64:
                        return Architecture.Arm64;
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_I386:
                        return Architecture.X86;
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_AMD64:
                    case SystemInfo.MachineType.IMAGE_FILE_MACHINE_I860:
                        return Architecture.X64;
                    default:
                        return RuntimeInformation.OSArchitecture;
                }
            }

            public class WindowsVersionInfo
            {
                public int MajorVersion { get; set; }
                public int BuildNumber { get; set; }
                public int UpdateNumber { get; set; }
                public string Edition { get; set; } = null!;
            }

            public static WindowsVersionInfo RtlGetVersion()
            {
                var result = new WindowsVersionInfo();

                bool failed = false;
                try
                {
                    result.BuildNumber = Int32.Parse((string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber", (string)"-1")!);
                    result.UpdateNumber = (int)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", (int)0)!;
                    failed = result.BuildNumber == -1;
                }
                catch (Exception e)
                {
                    failed = true;
                }

                try
                {
                    SystemInfo.RTL_OSVERSIONINFOEX v = new SystemInfo.RTL_OSVERSIONINFOEX();
                    v.dwOSVersionInfoSize = (uint)Marshal.SizeOf<SystemInfo.RTL_OSVERSIONINFOEX>();
                    if (SystemInfo.RtlGetVersion(ref v) == 0)
                    {
                        result.BuildNumber = result.BuildNumber > (int)v.dwBuildNumber ? result.BuildNumber : (int)v.dwBuildNumber;
                        result.MajorVersion = result.BuildNumber < 22000 ? 10 : 11;
                        result.MajorVersion = result.MajorVersion > (int)v.dwMajorVersion ? result.MajorVersion : (int)v.dwMajorVersion;
                        failed = false;
                    }
                    else
                        result.MajorVersion = result.BuildNumber < 22000 ? 10 : 11;
                }
                catch (Exception e)
                {
                    result.MajorVersion = result.BuildNumber < 22000 ? 10 : 11;
                }
                if (failed)
                    throw new Exception("RtlGetVersion failed.");

                try
                {
                    var edition = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID", "Core")!;
                    result.Edition = edition switch
                    {
                        "Core" => "Home",
                        "Professional" => "Pro",
                        "ProfessionalWorkstation" => "Pro Workstation",
                        "Enterprise" => "Enterprise",
                        "EnterpriseN" => "Enterprise",
                        "EnterpriseG" => "Enterprise",
                        "EnterpriseS" => "Enterprise S",
                        "EnterpriseSN" => "Enterprise S",
                        "Education" => "Education",
                        "ProfessionalEducation" => "Pro Education",
                        "ServerStandard" => "Server",
                        "ServerDatacenter" => "Server",
                        "ServerSolution" => "Server",
                        "ServerStandardEval" => "Server Eval",
                        "ServerDatacenterEval" => "Server Eval",
                        "Cloud" => "Cloud",
                        "CloudN" => "Cloud S",
                        "CoreCountrySpecific" => "Home",
                        "CoreSingleLanguage" => "Home",
                        "IoTCore" => "IoT Core",
                        "IoTEnterprise" => "IoT Enterprise",
                        "IoTEnterpriseS" => "IoT Enterprise S",
                        "IoTUAP" => "IoT Enterprise",
                        "Team" => "Team",
                        _ => String.IsNullOrWhiteSpace(edition) ? "Home" : edition
                    };
                }
                catch (Exception e)
                {
                    result.Edition = "Home";
                }

                return result;
            }
        }

        public static class Resource
        {
            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool DestroyIcon(IntPtr hIcon);

            [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadImage(IntPtr hInstance, string lpIconName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadLibrary(string lpFileName);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FreeLibrary(IntPtr hModule);

            public const uint IMAGE_ICON = 1;
            public const uint LR_SHARED = 0x00008000;
            public const uint LR_DEFAULTSIZE = 0x00000040;
        }

        public static class ResourceEx { }

        public static class Service
        {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
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
                [Optional] string lpdwTagId, // only string so we can pass null
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

            public const int STANDARD_RIGHTS_REQUIRED = 0xF0000;
            public const int SERVICE_WIN32_OWN_PROCESS = 0x00000010;

            [StructLayout(LayoutKind.Sequential)]
            public class SERVICE_STATUS
            {
                public int dwServiceType = 0;
                public ServiceState dwCurrentState = 0;
                public int dwControlsAccepted = 0;
                public int dwWin32ExitCode = 0;
                public int dwServiceSpecificExitCode = 0;
                public int dwCheckPoint = 0;
                public int dwWaitHint = 0;
            }

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, ServiceAccessRights dwDesiredAccess, int dwServiceType, ServiceBootFlag dwStartType,
                ServiceError dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lp, string lpPassword);

            [DllImport("advapi32.dll")]
            public static extern int QueryServiceStatus(IntPtr hService, SERVICE_STATUS lpServiceStatus);


            [DllImport("advapi32.dll")]
            public static extern int ControlService(IntPtr hService, ServiceControl dwControl, SERVICE_STATUS lpServiceStatus);


            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern int StartService(IntPtr hService, int dwNumServiceArgs, int lpServiceArgVectors);

            public enum ServiceState
            {
                Unknown = -1, // The state cannot be (has not been) retrieved.
                NotFound = 0, // The service is not known on the host server.
                Stopped = 1,
                StartPending = 2,
                StopPending = 3,
                Running = 4,
                ContinuePending = 5,
                PausePending = 6,
                Paused = 7
            }

            [Flags]
            public enum ScmAccessRights
            {
                Connect = 0x0001,
                CreateService = 0x0002,
                EnumerateService = 0x0004,
                Lock = 0x0008,
                QueryLockStatus = 0x0010,
                ModifyBootConfig = 0x0020,
                StandardRightsRequired = 0xF0000,
                AllAccess = (StandardRightsRequired | Connect | CreateService |
                    EnumerateService | Lock | QueryLockStatus | ModifyBootConfig)
            }

            [Flags]
            public enum ServiceAccessRights
            {
                QueryConfig = 0x1,
                ChangeConfig = 0x2,
                QueryStatus = 0x4,
                EnumerateDependants = 0x8,
                Start = 0x10,
                Stop = 0x20,
                PauseContinue = 0x40,
                Interrogate = 0x80,
                UserDefinedControl = 0x100,
                Delete = 0x00010000,
                StandardRightsRequired = 0xF0000,
                AllAccess = (StandardRightsRequired | QueryConfig | ChangeConfig |
                    QueryStatus | EnumerateDependants | Start | Stop | PauseContinue |
                    Interrogate | UserDefinedControl)
            }

            public enum ServiceBootFlag
            {
                Start = 0x00000000,
                SystemStart = 0x00000001,
                AutoStart = 0x00000002,
                DemandStart = 0x00000003,
                Disabled = 0x00000004
            }

            public enum ServiceControl
            {
                Stop = 0x00000001,
                Pause = 0x00000002,
                Continue = 0x00000003,
                Interrogate = 0x00000004,
                Shutdown = 0x00000005,
                ParamChange = 0x00000006,
                NetBindAdd = 0x00000007,
                NetBindRemove = 0x00000008,
                NetBindEnable = 0x00000009,
                NetBindDisable = 0x0000000A
            }

            public enum ServiceError
            {
                Ignore = 0x00000000,
                Normal = 0x00000001,
                Severe = 0x00000002,
                Critical = 0x00000003
            }

            public struct ENUM_SERVICE_STATUS_PROCESS
            {
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
                SERVICE_DELETE = 0x00010000,
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

        public static class ServiceEx
        {
            public static bool IsPendingDeleteOrDeleted(string serviceName)
            {
                var manager = Service.OpenSCManager(null, null, Service.SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
                if (manager == IntPtr.Zero)
                    return new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 }.GetStatus() ==
                        UninstallTaskStatus.Completed ||
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
                    return new RegistryValueAction() { KeyName = @"HKLM\SYSTEM\CurrentControlSet\Services\" + serviceName, Value = "DeleteFlag", Type = RegistryValueType.REG_DWORD, Data = 1 }.GetStatus() ==
                        UninstallTaskStatus.Completed ||
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
            public static extern bool OpenProcessToken(SafeProcessHandle hProcess, TokenAccessFlags DesiredAccess,
                out TokensEx.SafeTokenHandle hToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool GetTokenInformation(TokensEx.SafeTokenHandle TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength,
                out int ReturnLength);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool GetTokenInformation(TokensEx.SafeTokenHandle TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass, out int TokenInformation, int TokenInformationLength,
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
                ref int pTokenInfo,
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

                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
                public SID.SID_AND_ATTRIBUTES[] Groups;

                public TOKEN_GROUPS(int privilegeCount)
                {
                    GroupCount = privilegeCount;
                    Groups = new SID.SID_AND_ATTRIBUTES[64];
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
                SE_PRIVILEGE_DISABLED = 0x00000000,
                SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
                SE_PRIVILEGE_ENABLED = 0x00000002,
                SE_PRIVILEGE_REMOVED = 0x00000004,
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
                    : base(ownsHandle: true) { }

                protected override bool ReleaseHandle()
                {
                    return Win32.CloseHandle(handle);
                }
            }

            public static Tokens.TOKEN_PRIVILEGES CreateTokenPrivileges(string[] privs)
            {
                Tokens.TOKEN_PRIVILEGES tokenPrivileges;
                var sizeOfStruct = Marshal.SizeOf(typeof(Tokens.TOKEN_PRIVILEGES));
                var pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);
                tokenPrivileges = (Tokens.TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pPrivileges, typeof(Tokens.TOKEN_PRIVILEGES));
                tokenPrivileges.PrivilegeCount = privs.Length;
                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    if (!Win32.Tokens.LookupPrivilegeValue(IntPtr.Zero, privs[idx], out var luid))
                    {
                        tokenPrivileges.PrivilegeCount--;
                        Log.EnqueueSafe(LogType.Warning, "Failed to lookup privilege " + privs[idx] + ".", new SerializableTrace());
                        continue;
                    }
                    tokenPrivileges.Privileges[idx].Attributes =
                        (uint)(Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                            Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                    tokenPrivileges.Privileges[idx].Luid = luid;
                }
                return tokenPrivileges;
            }

            public static Tokens.TOKEN_PRIVILEGES CreateDefaultAdministratorTokenPrivileges()
            {
                Tokens.TOKEN_PRIVILEGES tokenPrivileges;
                var privs = new string[]
                {
                    Win32.Tokens.SE_INCREASE_QUOTA_NAME,
                    Win32.Tokens.SE_SECURITY_NAME,
                    Win32.Tokens.SE_TAKE_OWNERSHIP_NAME,
                    Win32.Tokens.SE_LOAD_DRIVER_NAME,
                    Win32.Tokens.SE_SYSTEM_PROFILE_NAME,
                    Win32.Tokens.SE_SYSTEMTIME_NAME,
                    Win32.Tokens.SE_PROFILE_SINGLE_PROCESS_NAME,
                    Win32.Tokens.SE_INCREASE_BASE_PRIORITY_NAME,
                    Win32.Tokens.SE_CREATE_PAGEFILE_NAME,
                    Win32.Tokens.SE_BACKUP_NAME,
                    Win32.Tokens.SE_RESTORE_NAME,
                    Win32.Tokens.SE_SHUTDOWN_NAME,
                    Win32.Tokens.SE_DEBUG_NAME,
                    Win32.Tokens.SE_SYSTEM_ENVIRONMENT_NAME,
                    Win32.Tokens.SE_REMOTE_SHUTDOWN_NAME,
                    Win32.Tokens.SE_UNDOCK_NAME,
                    Win32.Tokens.SE_MANAGE_VOLUME_NAME,
                    Win32.Tokens.SE_INCREASE_WORKING_SET_NAME,
                    Win32.Tokens.SE_TIME_ZONE_NAME,
                    Win32.Tokens.SE_CREATE_SYMBOLIC_LINK_NAME,
                    Win32.Tokens.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,

                    Win32.Tokens.SE_IMPERSONATE_NAME,
                    Win32.Tokens.SE_CHANGE_NOTIFY_NAME,
                    Win32.Tokens.SE_CREATE_GLOBAL_NAME,
                };
                var sizeOfStruct = Marshal.SizeOf(typeof(Tokens.TOKEN_PRIVILEGES));
                var pPrivileges = Marshal.AllocHGlobal(sizeOfStruct);
                tokenPrivileges = (Tokens.TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                    pPrivileges, typeof(Tokens.TOKEN_PRIVILEGES));
                tokenPrivileges.PrivilegeCount = privs.Length;
                for (var idx = 0; idx < tokenPrivileges.PrivilegeCount; idx++)
                {
                    if (!Win32.Tokens.LookupPrivilegeValue(IntPtr.Zero, privs[idx], out var luid))
                    {
                        tokenPrivileges.PrivilegeCount--;
                        Log.EnqueueSafe(LogType.Warning, "Failed to lookup privilege " + privs[idx] + ".", new SerializableTrace());
                        continue;
                    }

                    if (privs[idx] == Win32.Tokens.SE_CHANGE_NOTIFY_NAME || privs[idx] == Win32.Tokens.SE_IMPERSONATE_NAME || privs[idx] == Win32.Tokens.SE_CREATE_GLOBAL_NAME)
                    {
                        tokenPrivileges.Privileges[idx].Attributes =
                            (uint)(Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED |
                                Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_ENABLED_BY_DEFAULT);
                    }
                    else
                    {
                        tokenPrivileges.Privileges[idx].Attributes =
                            (uint)(Tokens.SE_PRIVILEGE_ATTRIBUTES.SE_PRIVILEGE_DISABLED);
                    }
                    tokenPrivileges.Privileges[idx].Luid = luid;
                }
                return tokenPrivileges;
            }

            public static void AdjustCurrentPrivilege(string privilege)
            {
                Win32.Tokens.LookupPrivilegeValue(IntPtr.Zero, privilege, out LUID luid);
                Win32.Tokens.RtlAdjustPrivilege(luid, true, true, out _);
            }

            public static IntPtr GetInfoFromToken(SafeTokenHandle token, Win32.Tokens.TOKEN_INFORMATION_CLASS information, int size)
            {
                Win32.Tokens.GetTokenInformation(token, information, IntPtr.Zero, 0, out int length);
                var result = Marshal.AllocHGlobal(Math.Max(size, length));
                Win32.Tokens.GetTokenInformation(token, information, result, length, out length);
                return result;
            }
        }

        public static class Process
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern SafeProcessHandle GetCurrentProcess();

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint lpExitCode);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint WaitForSingleObject(SafeProcessHandle process, uint dwMilliseconds);

            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, TokensEx.SafeTokenHandle hToken, bool bInherit);
            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessAsUser(Win32.TokensEx.SafeTokenHandle hToken, string lpApplicationName, StringBuilder lpCommandLine, SECURITY_ATTRIBUTES lpProcessAttributes,
                SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);

            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool CreateProcessWithToken(TokensEx.SafeTokenHandle hToken, LogonFlags dwLogonFlags,
                string lpApplicationName, string lpCommandLine, ProcessCreationFlags dwCreationFlags,
                IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern SafeProcessHandle OpenProcess(ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle, int dwProcessId);

            [DllImport("ntdll.dll")]
            public static extern int NtQueryInformationProcess(SafeProcessHandle process, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength,
                out int returnLength);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint dwFlags,
                [Out, MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpExeName, ref uint lpdwSize);

            [DllImport("kernel32.dll")]
            public static extern bool TerminateProcess(SafeProcessHandle process, uint uExitCode);


            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr ExitStatus;
                public IntPtr PebBaseAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public UIntPtr UniqueProcessId;
                public UIntPtr InheritedFromUniqueProcessId;
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }

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

        public static class ProcessEx
        {
            [CanBeNull]
            public static System.Diagnostics.Process GetCurrentParentProcess()
            {
                return GetParentProcess(Process.GetCurrentProcess());
            }

            [CanBeNull]
            public static System.Diagnostics.Process GetParentProcess(SafeProcessHandle handle)
            {
                try
                {
                    Process.PROCESS_BASIC_INFORMATION pbi = new Process.PROCESS_BASIC_INFORMATION();
                    int status = Process.NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                    if (status != 0)
                        throw new ApplicationException("Could not get parent process.");

                    return System.Diagnostics.Process.GetProcessById((int)pbi.InheritedFromUniqueProcessId);
                }
                catch (Exception)
                {
                    return null;
                }
            }

            public static string GetCurrentProcessFileLocation()
            {
                var exe = new StringBuilder(1024);
                uint size = 1024;
                using var process = Process.GetCurrentProcess();
                if (!Process.QueryFullProcessImageName(process, 0, exe, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not fetch active process path.");

                return exe.ToString();
            }
            public static string GetProcessFileLocation(int processId)
            {
                using var process = Process.OpenProcess(Process.ProcessAccessFlags.QueryLimitedInformation, false, processId);
                if (process.DangerousGetHandle() == INVALID_HANDLE_VALUE)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not fetch process handle for path.");

                var exe = new StringBuilder(1024);
                uint size = 1024;
                if (!Process.QueryFullProcessImageName(process, 0, exe, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not fetch active process path.");

                return exe.ToString();
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
            public class SafeSIDHandle : SafeHandleZeroOrMinusOneIsInvalid
            {

                public SafeSIDHandle() : base(true) { }

                // Provide a constructor to set the handle
                public SafeSIDHandle(IntPtr handle) : base(true)
                {
                    SetHandle(handle);
                }

                override protected bool ReleaseHandle()
                {
                    FreeSid(handle);
                    return true;
                }
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool AllocateAndInitializeSid(ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2,
                int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7,
                out SafeSIDHandle pSid);

            [DllImport("advapi32.dll")]
            public static extern bool AllocateLocallyUniqueId(out LUID allocated);

            [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ConvertStringSidToSid(string StringSid, out SafeSIDHandle ptrSid);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetLengthSid(SafeSIDHandle pSid);

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
            public const string NT_SERVICE_SID = "S-1-5-6";

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
            public static extern bool WTSQuerySessionInformation(IntPtr hServer, UInt32 sessionId, WTS_INFO_CLASS wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

            [DllImport("wtsapi32.dll")]
            public static extern void WTSFreeMemory(IntPtr pMemory);

            public enum WTS_INFO_CLASS
            {
                WTSInitialProgram,
                WTSApplicationName,
                WTSWorkingDirectory,
                WTSOEMId,
                WTSSessionId,
                WTSUserName,
                WTSWinStationName,
                WTSDomainName,
                WTSConnectState,
                WTSClientBuildNumber,
                WTSClientName,
                WTSClientDirectory,
                WTSClientProductId,
                WTSClientHardwareId,
                WTSClientAddress,
                WTSClientDisplay,
                WTSClientProtocolType,
                WTSIdleTime,
                WTSLogonTime,
                WTSIncomingBytes,
                WTSOutgoingBytes,
                WTSIncomingFrames,
                WTSOutgoingFrames,
                WTSClientInfo,
                WTSSessionInfo
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct WTS_CLIENT_ADDRESS
            {
                public uint AddressFamily;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
                public byte[] Address;
            }

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

        #region ISO Mode
        [DllImport("kernel32.dll")]
        public static extern bool DefineDosDevice(uint dwFlags, string lpDeviceName,
            string lpTargetPath);

        [DllImport("Kernel32.dll")]
        public static extern uint QueryDosDevice(string lpDeviceName,
            string lpTargetPath, uint ucchMax);

        public const uint DDD_RAW_TARGET_PATH = 0x00000001;
        public const uint DDD_REMOVE_DEFINITION = 0x00000002;
        public const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;
        public const uint DDD_NO_BROADCAST_SYSTEM = 0x00000008;

        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        public static extern void ZeroMemory(IntPtr dest, uint size);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string Enumerator, IntPtr hwndParent, uint Flags);

        [DllImport(@"setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean SetupDiEnumDeviceInterfaces(IntPtr hDevInfo, ref SP_DEVINFO_DATA devInfo,
            ref Guid interfaceClassGuid, UInt32 memberIndex, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

        [DllImport(@"setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean SetupDiGetDeviceInterfaceDetail(IntPtr hDevInfo,
            ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
            ref SP_DEVICE_INTERFACE_DETAIL_DATA deviceInterfaceDetailData, UInt32 deviceInterfaceDetailDataSize,
            ref UInt32 requiredSize, IntPtr deviceInfoData);

        [DllImport(@"setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean SetupDiGetDeviceInterfaceDetail(IntPtr hDevInfo,
            ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData, IntPtr deviceInterfaceDetailData,
            UInt32 deviceInterfaceDetailDataSize, ref UInt32 requiredSize, IntPtr deviceInfoData);

        [DllImport(@"setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean SetupDiEnumDeviceInfo(IntPtr hDevInfo, UInt32 memberIndex,
            ref SP_DEVINFO_DATA devInfo);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern Boolean SetupDiGetDeviceRegistryProperty(IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData, UInt32 property, out UInt32 propertyRegDataType, IntPtr propertyBuffer,
            UInt32 propertyBufferSize, out UInt32 requiredSize);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId, uint DeviceInstanceIdSize, out uint RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_DevNode_Property_Keys(UInt32 dnDevInst, [Out] IntPtr propertyKeyArray,
            ref UInt32 propertyKeyCount, UInt32 flags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_DevNode_Property(UInt32 dnDevInst, ref DEVPROPKEY propertyKey,
            out UInt32 propertyType, IntPtr propertyBuffer, ref UInt32 propertyBufferSize, UInt32 flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern int CM_Get_Device_ID_Size(out uint pulLen, UInt32 dnDevInst, int flags = 0);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern int CM_Get_Device_ID(uint dnDevInst, StringBuilder Buffer, int BufferLen,
            int ulFlags = 0);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern int CM_Get_Child(out uint pdnDevInst, UInt32 dnDevInst, int ulFlags = 0);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern int CM_Get_Sibling(out uint pdnDevInst, UInt32 dnDevInst, int ulFlags = 0);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern int CM_Locate_DevNodeA(ref uint pdnDevInst, string pDeviceID, int ulFlags = 0);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);


        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            ref DRIVE_LAYOUT_INFORMATION_EX lpInBuffer, uint nInBufferSize,
            IntPtr lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(
            [MarshalAs(UnmanagedType.LPTStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] FileAccess access,
            [MarshalAs(UnmanagedType.U4)] FileShare share,
            IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll")]
        public static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer,
            uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
            [In] ref System.Threading.NativeOverlapped lpOverlapped);

        [DllImport("kernel32.dll")]
        public static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer,
            uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
            [In] IntPtr lpOverlapped);

        [DllImport("kernel32.dll", EntryPoint = "RtlFillMemory", SetLastError = false)]
        public static extern void FillMemory(IntPtr destination, uint length, byte fill);

        // Win32 Items

        public const string GUID_DEVINTERFACE_USB_HUB = "{F18A0E88-C30C-11D0-8815-00A0C906BED8}";
        public const string GUID_DEVINTERFACE_DISK = "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}";

        // Common Return Codes
        public const int CR_SUCCESS = 0;

        [StructLayout(LayoutKind.Sequential)]
        public struct DEVPROPKEY
        {
            public Guid Fmtid;
            public UInt32 Pid;
        }

        public static class DevicePropertyTypes
        {
            public const UInt32 DEVPROP_TYPEMOD_ARRAY = 0x00001000;
            public const UInt32 DEVPROP_TYPEMOD_LIST = 0x00002000;
            public const UInt32 DEVPROP_TYPE_EMPTY = 0x00000000;
            public const UInt32 DEVPROP_TYPE_NULL = 0x00000001;
            public const UInt32 DEVPROP_TYPE_SBYTE = 0x00000002;
            public const UInt32 DEVPROP_TYPE_BYTE = 0x00000003;
            public const UInt32 DEVPROP_TYPE_INT16 = 0x00000004;
            public const UInt32 DEVPROP_TYPE_UINT16 = 0x00000005;
            public const UInt32 DEVPROP_TYPE_INT32 = 0x00000006;
            public const UInt32 DEVPROP_TYPE_UINT32 = 0x00000007;
            public const UInt32 DEVPROP_TYPE_INT64 = 0x00000008;
            public const UInt32 DEVPROP_TYPE_UINT64 = 0x00000009;
            public const UInt32 DEVPROP_TYPE_FLOAT = 0x0000000A;
            public const UInt32 DEVPROP_TYPE_DOUBLE = 0x0000000B;
            public const UInt32 DEVPROP_TYPE_DECIMAL = 0x0000000C;
            public const UInt32 DEVPROP_TYPE_GUID = 0x0000000D;
            public const UInt32 DEVPROP_TYPE_CURRENCY = 0x0000000E;
            public const UInt32 DEVPROP_TYPE_DATE = 0x0000000F;
            public const UInt32 DEVPROP_TYPE_FILETIME = 0x00000010;
            public const UInt32 DEVPROP_TYPE_BOOLEAN = 0x00000011;
            public const UInt32 DEVPROP_TYPE_STRING = 0x00000012;
            public const UInt32 DEVPROP_TYPE_STRING_LIST = DEVPROP_TYPE_STRING | DEVPROP_TYPEMOD_LIST;
            public const UInt32 DEVPROP_TYPE_SECURITY_DESCRIPTOR = 0x00000013;
            public const UInt32 DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING = 0x00000014;
            public const UInt32 DEVPROP_TYPE_DEVPROPKEY = 0x00000015;
            public const UInt32 DEVPROP_TYPE_DEVPROPTYPE = 0x00000016;
            public const UInt32 DEVPROP_TYPE_BINARY = DEVPROP_TYPE_BYTE | DEVPROP_TYPEMOD_ARRAY;
            public const UInt32 DEVPROP_TYPE_ERROR = 0x00000017;
            public const UInt32 DEVPROP_TYPE_NTSTATUS = 0x00000018;
            public const UInt32 DEVPROP_TYPE_STRING_INDIRECT = 0x00000019;
            public const UInt32 MAX_DEVPROP_TYPE = 0x00000019;
            public const UInt32 MAX_DEVPROP_TYPEMOD = 0x00002000;
            public const UInt32 DEVPROP_MASK_TYPE = 0x00000FFF;
            public const UInt32 DEVPROP_MASK_TYPEMOD = 0x0000F000;
        }

        public static class DevicePropertyKeys
        {
            public static readonly DEVPROPKEY DEVPKEY_NAME = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xb725f130, 0x47ef, 0x101a, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DeviceDesc = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_HardwareIds = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_CompatibleIds = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Service = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Class = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 9
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ClassGuid = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Driver = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 11
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ConfigFlags = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 12
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Manufacturer = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 13
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_FriendlyName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 14
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LocationInfo = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 15
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PDOName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 16
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Capabilities = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 17
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_UINumber = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 18
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_UpperFilters = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 19
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LowerFilters = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 20
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BusTypeGuid = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 21
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LegacyBusType = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 22
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BusNumber = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 23
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_EnumeratorName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 24
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Security = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 25
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_SecuritySDS = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 26
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DevType = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 27
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Exclusive = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 28
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Characteristics = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 29
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Address = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 30
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_UINumberDescFormat = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 31
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PowerData = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 32
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RemovalPolicy = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 33
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RemovalPolicyDefault = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 34
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RemovalPolicyOverride = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 35
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_InstallState = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 36
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LocationPaths = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 37
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BaseContainerId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0), Pid = 38
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DevNodeStatus = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ProblemCode = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_EjectionRelations = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RemovalRelations = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PowerRelations = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BusRelations = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Parent = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 8
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Children = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 9
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Siblings = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_TransportRelations = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 11
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ProblemStatus = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7), Pid = 12
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Reported = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80497100, 0x8c73, 0x48b9, 0xaa, 0xd9, 0xce, 0x38, 0x7e, 0x19, 0xc5, 0x6e), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Legacy = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80497100, 0x8c73, 0x48b9, 0xaa, 0xd9, 0xce, 0x38, 0x7e, 0x19, 0xc5, 0x6e), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ContainerId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x8c7ed206, 0x3f8a, 0x4827, 0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_InLocalMachineContainer = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x8c7ed206, 0x3f8a, 0x4827, 0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ModelId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_FriendlyNameAttributes = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ManufacturerAttributes = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PresenceNotForDevice = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_SignalStrength = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_IsAssociateableByUserAction = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_Numa_Proximity_Domain = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 1
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DHP_Rebalance_Policy = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Numa_Node = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BusReportedDeviceDesc = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_IsPresent = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_HasProblem = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ConfigurationId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_ReportedDeviceIdsHash = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 8
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PhysicalDeviceLocation = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 9
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_BiosDeviceName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverProblemDesc = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 11
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DebuggerSafe = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 12
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_PostInstallInProgress = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2), Pid = 13
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_SessionId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_InstallDate = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 100
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_FirstInstallDate = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 101
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LastArrivalDate = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 102
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_LastRemovalDate = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 103
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverDate = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverVersion = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverDesc = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverInfPath = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverInfSection = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverInfSectionExt = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_MatchingDeviceId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 8
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverProvider = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 9
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverPropPageProvider = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverCoInstallers = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 11
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RepropertyBufferPickerTags = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 12
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_RepropertyBufferPickerExceptions = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 13
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverRank = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 14
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_DriverLogoLevel = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 15
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_NoConnectSound = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 17
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_GenericDriverInstalled = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 18
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_AdditionalSoftwareRequested = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6), Pid = 19
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_SafeRemovalRequired = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xafd97640, 0x86a3, 0x4210, 0xb6, 0x7c, 0x28, 0x9c, 0x41, 0xaa, 0xbe, 0x55), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_SafeRemovalRequiredOverride = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xafd97640, 0x86a3, 0x4210, 0xb6, 0x7c, 0x28, 0x9c, 0x41, 0xaa, 0xbe, 0x55), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_Model = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_VendorWebSite = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_DetailedDescription = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_DocumentationLink = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_Icon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_DrvPkg_BrandingIcon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_UpperFilters = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 19
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_LowerFilters = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 20
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_Security = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 25
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_SecuritySDS = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 26
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_DevType = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 27
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_Exclusive = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 28
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_Characteristics = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b), Pid = 29
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_Name = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_ClassName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_Icon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_ClassInstaller = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_PropPageProvider = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_NoInstallClass = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 7
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_NoDisplayClass = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 8
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_SilentInstall = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 9
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_NoUseClass = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 10
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_DefaultService = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 11
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_IconPath = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66), Pid = 12
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_DHPRebalanceOptOut = new DEVPROPKEY()
            {
                Fmtid = new Guid(0xd14d3ef3, 0x66cf, 0x4ba2, 0x9d, 0x38, 0x0d, 0xdb, 0x37, 0xab, 0x47, 0x01), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceClass_ClassCoInstallers = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x713d1703, 0xa2e2, 0x49f5, 0x92, 0x14, 0x56, 0x47, 0x2e, 0xf3, 0xda, 0x5c), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterface_FriendlyName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterface_Enabled = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterface_ClassGuid = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22), Pid = 4
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterface_ReferenceString = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22), Pid = 5
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterface_Restricted = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22), Pid = 6
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterfaceClass_DefaultInterface = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x14c83a99, 0x0b3f, 0x44b7, 0xbe, 0x4c, 0xa1, 0x78, 0xd3, 0x99, 0x05, 0x64), Pid = 2
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceInterfaceClass_Name = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x14c83a99, 0x0b3f, 0x44b7, 0xbe, 0x4c, 0xa1, 0x78, 0xd3, 0x99, 0x05, 0x64), Pid = 3
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_Model = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 39
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Address = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 51
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_DiscoveryMethod = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 52
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsEncrypted = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 53
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsAuthenticated = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 54
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsConnected = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 55
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsPaired = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 56
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Icon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 57
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Version = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 65
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Last_Seen = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 66
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Last_Connected = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 67
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsShowInDisconnectedState = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 68
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsLocalMachine = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 70
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_MetadataPath = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 71
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsMetadataSearchInProgress = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 72
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_MetadataChecksum = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 73
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsNotInterestingForDisplay = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 74
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_LaunchDeviceStageOnDeviceConnect =
                new DEVPROPKEY()
                {
                    Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57),
                    Pid = 76
                };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_LaunchDeviceStageFromExplorer = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 77
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_BaselineExperienceId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 78
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsDeviceUniquelyIdentifiable = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 79
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_AssociationArray = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 80
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_DeviceDescription1 = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 81
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_DeviceDescription2 = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 82
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_HasProblem = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 83
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsSharedDevice = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 84
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsNetworkDevice = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 85
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsDefaultDevice = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 86
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_MetadataCabinet = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 87
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_RequiresPairingElevation = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 88
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_ExperienceId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 89
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Category = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 90
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Category_Desc_Singular = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 91
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Category_Desc_Plural = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 92
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Category_Icon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 93
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_CategoryGroup_Desc = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 94
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_CategoryGroup_Icon = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 95
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_PrimaryCategory = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 97
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_UnpairUninstall = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 98
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_RequiresUninstallElevation = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 99
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_DeviceFunctionSubRank = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 100
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_AlwaysShowDeviceAsConnected = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 101
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_ConfigFlags = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 105
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_PrivilegedPackageFamilyNames = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 106
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_CustomPrivilegedPackageFamilyNames =
                new DEVPROPKEY()
                {
                    Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57),
                    Pid = 107
                };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_IsRebootRequired = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 108
            };

            public static readonly DEVPROPKEY DEVPKEY_Device_InstanceId = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57), Pid = 256
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_FriendlyName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x656A3BB3, 0xECC0, 0x43FD, 0x84, 0x77, 0x4A, 0xE0, 0x40, 0x4A, 0x96, 0xCD),
                Pid = 12288
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_Manufacturer = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x656A3BB3, 0xECC0, 0x43FD, 0x84, 0x77, 0x4A, 0xE0, 0x40, 0x4A, 0x96, 0xCD), Pid = 8192
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_ModelName = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x656A3BB3, 0xECC0, 0x43FD, 0x84, 0x77, 0x4A, 0xE0, 0x40, 0x4A, 0x96, 0xCD), Pid = 8194
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_ModelNumber = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x656A3BB3, 0xECC0, 0x43FD, 0x84, 0x77, 0x4A, 0xE0, 0x40, 0x4A, 0x96, 0xCD), Pid = 8195
            };

            public static readonly DEVPROPKEY DEVPKEY_DeviceContainer_InstallInProgress = new DEVPROPKEY()
            {
                Fmtid = new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29), Pid = 9
            };
        }

        [Flags]
        public enum DiGetClassFlags : uint
        {
            DIGCF_DEFAULT = 0x00000001, // only valid with DIGCF_DEVICEINTERFACE
            DIGCF_PRESENT = 0x00000002,
            DIGCF_ALLCLASSES = 0x00000004,
            DIGCF_PROFILE = 0x00000008,
            DIGCF_DEVICEINTERFACE = 0x00000010,
        }

        [Flags]
        public enum CmFlags : uint
        {
            CM_GETIDLIST_FILTER_SERVICE = 0x00000002,
            CM_GETIDLIST_FILTER_PRESENT = 0x00000100,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVICE_INTERFACE_DATA
        {
            public Int32 cbSize;
            public Guid interfaceClassGuid;
            public Int32 flags;
            public UIntPtr reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVINFO_DATA
        {
            public UInt32 cbSize;
            public Guid ClassGuid;
            public UInt32 DevInst;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            public int cbSize;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DevicePath;
        }

        const ulong CM_GETIDLIST_FILTER_PRESENT = 0x00000100;
        const ulong CM_GETIDLIST_FILTER_SERVICE = 0x00000002;

        public enum SPDRP
        {
            SPDRP_DEVICEDESC = 0,
            SPDRP_HARDWAREID = 0x1,
            SPDRP_COMPATIBLEIDS = 0x2,
            SPDRP_UNUSED0 = 0x3,
            SPDRP_SERVICE = 0x4,
            SPDRP_UNUSED1 = 0x5,
            SPDRP_UNUSED2 = 0x6,
            SPDRP_CLASS = 0x7,
            SPDRP_CLASSGUID = 0x8,
            SPDRP_DRIVER = 0x9,
            SPDRP_CONFIGFLAGS = 0xa,
            SPDRP_MFG = 0xb,
            SPDRP_FRIENDLYNAME = 0xc,
            SPDRP_LOCATION_INFORMATION = 0xd,
            SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0xe,
            SPDRP_CAPABILITIES = 0xf,
            SPDRP_UI_NUMBER = 0x10,
            SPDRP_UPPERFILTERS = 0x11,
            SPDRP_LOWERFILTERS = 0x12,
            SPDRP_BUSTYPEGUID = 0x13,
            SPDRP_LEGACYBUSTYPE = 0x14,
            SPDRP_BUSNUMBER = 0x15,
            SPDRP_ENUMERATOR_NAME = 0x16,
            SPDRP_SECURITY = 0x17,
            SPDRP_SECURITY_SDS = 0x18,
            SPDRP_DEVTYPE = 0x19,
            SPDRP_EXCLUSIVE = 0x1a,
            SPDRP_CHARACTERISTICS = 0x1b,
            SPDRP_ADDRESS = 0x1c,
            SPDRP_UI_NUMBER_DESC_FORMAT = 0x1e,
            SPDRP_MAXIMUM_PROPERTY = 0x1f
        }

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

            FILE_ALL_ACCESS =
                StandardRightsRequired |
                Synchronize |
                0x1FF,

            FILE_GENERIC_READ =
                StandardRightsRead |
                FILE_READ_DATA |
                FILE_READ_ATTRIBUTES |
                FILE_READ_EA |
                Synchronize,

            FILE_GENERIC_WRITE =
                StandardRightsWrite |
                FILE_WRITE_DATA |
                FILE_WRITE_ATTRIBUTES |
                FILE_WRITE_EA |
                FILE_APPEND_DATA |
                Synchronize,

            FILE_GENERIC_EXECUTE =
                StandardRightsExecute |
                FILE_READ_ATTRIBUTES |
                FILE_EXECUTE |
                Synchronize
        }

        [Flags]
        public enum FileShare : uint
        {
            /// <summary>
            ///
            /// </summary>
            None = 0x00000000,

            /// <summary>
            /// Enables subsequent open operations on an object to request read access.
            /// Otherwise, other processes cannot open the object if they request read access.
            /// If this flag is not specified, but the object has been opened for read access, the function fails.
            /// </summary>
            Read = 0x00000001,

            /// <summary>
            /// Enables subsequent open operations on an object to request write access.
            /// Otherwise, other processes cannot open the object if they request write access.
            /// If this flag is not specified, but the object has been opened for write access, the function fails.
            /// </summary>
            Write = 0x00000002,

            /// <summary>
            /// Enables subsequent open operations on an object to request delete access.
            /// Otherwise, other processes cannot open the object if they request delete access.
            /// If this flag is not specified, but the object has been opened for delete access, the function fails.
            /// </summary>
            Delete = 0x00000004
        }

        public enum FileMode : uint
        {
            /// <summary>
            /// Creates a new file. The function fails if a specified file exists.
            /// </summary>
            New = 1,

            /// <summary>
            /// Creates a new file, always.
            /// If a file exists, the function overwrites the file, clears the existing attributes, combines the specified file attributes,
            /// and flags with FILE_ATTRIBUTE_ARCHIVE, but does not set the security descriptor that the SECURITY_ATTRIBUTES structure specifies.
            /// </summary>
            CreateAlways = 2,

            /// <summary>
            /// Opens a file. The function fails if the file does not exist.
            /// </summary>
            OpenExisting = 3,

            /// <summary>
            /// Opens a file, always.
            /// If a file does not exist, the function creates a file as if dwCreationDisposition is CREATE_NEW.
            /// </summary>
            OpenAlways = 4,

            /// <summary>
            /// Opens a file and truncates it so that its size is 0 (zero) bytes. The function fails if the file does not exist.
            /// The calling process must open the file with the GENERIC_WRITE access right.
            /// </summary>
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

        [StructLayout(LayoutKind.Sequential)]
        public class STORAGE_DEVICE_NUMBER
        {
            public uint DeviceType;
            public uint DeviceNumber;
            public uint PartitionNumber;
        }

        [StructLayout(LayoutKind.Sequential, Size = 8)]
        public class DISK_EXTENT
        {
            public uint DiskNumber;
            public long StartingOffset;
            public long ExtentLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class VOLUME_DISK_EXTENTS
        {
            public uint NumberOfDiskExtents;
            public DISK_EXTENT Extents;
        }

        /// <summary>
        /// Describes the geometry of disk devices and media.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct DISK_GEOMETRY
        {
            /// <summary>
            /// The number of cylinders.
            /// </summary>
            [FieldOffset(0)] public Int64 Cylinders;

            /// <summary>
            /// The type of media. For a list of values, see MEDIA_TYPE.
            /// </summary>
            [FieldOffset(8)] public MEDIA_TYPE MediaType;

            /// <summary>
            /// The number of tracks per cylinder.
            /// </summary>
            [FieldOffset(12)] public uint TracksPerCylinder;

            /// <summary>
            /// The number of sectors per track.
            /// </summary>
            [FieldOffset(16)] public uint SectorsPerTrack;

            /// <summary>
            /// The number of bytes per sector.
            /// </summary>
            [FieldOffset(20)] public uint BytesPerSector;
        }

        /*
        /// <summary>
        /// Describes the extended geometry of disk devices and media.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct DISK_GEOMETRY_EX
        {
            /// <summary>
            /// A DISK_GEOMETRY structure.
            /// </summary>
            [FieldOffset(0)] public DISK_GEOMETRY Geometry;

            /// <summary>
            /// The disk size, in bytes.
            /// </summary>
            [FieldOffset(24)] public Int64 DiskSize;

            /// <summary>
            /// Any additional data.
            /// </summary>
            [FieldOffset(32)] public Byte Data;
        }
        */

        [StructLayout(LayoutKind.Sequential)]
        public class DISK_GEOMETRY_EX
        {
            public DISK_GEOMETRY Geometry;
            public LARGE_INTEGER DiskSize;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] Data;
        }


        public enum MEDIA_TYPE : int
        {
            Unknown = 0,
            F5_1Pt2_512 = 1,
            F3_1Pt44_512 = 2,
            F3_2Pt88_512 = 3,
            F3_20Pt8_512 = 4,
            F3_720_512 = 5,
            F5_360_512 = 6,
            F5_320_512 = 7,
            F5_320_1024 = 8,
            F5_180_512 = 9,
            F5_160_512 = 10,
            RemovableMedia = 11,
            FixedMedia = 12,
            F3_120M_512 = 13,
            F3_640_512 = 14,
            F5_640_512 = 15,
            F5_720_512 = 16,
            F3_1Pt2_512 = 17,
            F3_1Pt23_1024 = 18,
            F5_1Pt23_1024 = 19,
            F3_128Mb_512 = 20,
            F3_230Mb_512 = 21,
            F8_256_128 = 22,
            F3_200Mb_512 = 23,
            F3_240M_512 = 24,
            F3_32M_512 = 25
        }

        /// <summary>
        /// Represents the format of a partition.
        /// </summary>
        public enum PARTITION_STYLE : uint
        {
            /// <summary>
            /// Master boot record (MBR) format.
            /// </summary>
            PARTITION_STYLE_MBR = 0,

            /// <summary>
            /// GUID Partition Table (GPT) format.
            /// </summary>
            PARTITION_STYLE_GPT = 1,

            /// <summary>
            /// Partition not formatted in either of the recognized formats—MBR or GPT.
            /// </summary>
            PARTITION_STYLE_RAW = 2
        }

        /// <summary>
        /// Contains partition information specific to master boot record (MBR) disks.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct PARTITION_INFORMATION_MBR
        {
            #region Constants
            /// <summary>
            /// An unused entry partition.
            /// </summary>
            public const byte PARTITION_ENTRY_UNUSED = 0x00;

            /// <summary>
            /// A FAT12 file system partition.
            /// </summary>
            public const byte PARTITION_FAT_12 = 0x01;

            /// <summary>
            /// A FAT16 file system partition.
            /// </summary>
            public const byte PARTITION_FAT_16 = 0x04;

            /// <summary>
            /// An extended partition.
            /// </summary>
            public const byte PARTITION_EXTENDED = 0x05;

            /// <summary>
            /// An IFS partition.
            /// </summary>
            public const byte PARTITION_IFS = 0x07;

            /// <summary>
            /// A FAT32 file system partition.
            /// </summary>
            public const byte PARTITION_FAT32 = 0x0B;

            /// <summary>
            /// A logical disk manager (LDM) partition.
            /// </summary>
            public const byte PARTITION_LDM = 0x42;

            /// <summary>
            /// An NTFT partition.
            /// </summary>
            public const byte PARTITION_NTFT = 0x80;

            /// <summary>
            /// A valid NTFT partition.
            /// 
            /// The high bit of a partition type code indicates that a partition is part of an NTFT mirror or striped array.
            /// </summary>
            public const byte PARTITION_VALID_NTFT = 0xC0;
            #endregion

            /// <summary>
            /// The type of partition. For a list of values, see Disk Partition Types.
            /// </summary>
            [FieldOffset(0)] [MarshalAs(UnmanagedType.U1)]
            public byte PartitionType;

            /// <summary>
            /// If this member is TRUE, the partition is bootable.
            /// </summary>
            [FieldOffset(1)] [MarshalAs(UnmanagedType.I1)]
            public bool BootIndicator;

            /// <summary>
            /// If this member is TRUE, the partition is of a recognized type.
            /// </summary>
            [FieldOffset(2)] [MarshalAs(UnmanagedType.I1)]
            public bool RecognizedPartition;

            /// <summary>
            /// The number of hidden sectors in the partition.
            /// </summary>
            [FieldOffset(4)] public uint HiddenSectors;
        }

        /// <summary>
        /// Contains GUID partition table (GPT) partition information.
        /// </summary>
        [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
        public struct PARTITION_INFORMATION_GPT
        {
            /// <summary>
            /// A GUID that identifies the partition type.
            /// 
            /// Each partition type that the EFI specification supports is identified by its own GUID, which is 
            /// published by the developer of the partition.
            /// </summary>
            [FieldOffset(0)] public Guid PartitionType;

            /// <summary>
            /// The GUID of the partition.
            /// </summary>
            [FieldOffset(16)] public Guid PartitionId;

            /// <summary>
            /// The Extensible Firmware Interface (EFI) attributes of the partition.
            /// 
            /// </summary>
            [FieldOffset(32)] public UInt64 Attributes;

            /// <summary>
            /// A wide-character string that describes the partition.
            /// </summary>
            [FieldOffset(40)] [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 36)]
            public string Name;
        }

        /// <summary>
        /// Provides information about a drive's master boot record (MBR) partitions.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct DRIVE_LAYOUT_INFORMATION_MBR
        {
            /// <summary>
            /// The signature of the drive.
            /// </summary>
            [FieldOffset(0)] public uint Signature;
        }

        /// <summary>
        /// Contains information about a drive's GUID partition table (GPT) partitions.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct DRIVE_LAYOUT_INFORMATION_GPT
        {
            /// <summary>
            /// The GUID of the disk.
            /// </summary>
            [FieldOffset(0)] public Guid DiskId;

            /// <summary>
            /// The starting byte offset of the first usable block.
            /// </summary>
            [FieldOffset(16)] public Int64 StartingUsableOffset;

            /// <summary>
            /// The size of the usable blocks on the disk, in bytes.
            /// </summary>
            [FieldOffset(24)] public Int64 UsableLength;

            /// <summary>
            /// The maximum number of partitions that can be defined in the usable block.
            /// </summary>
            [FieldOffset(32)] public uint MaxPartitionCount;
        }


        /// <summary>
        /// Contains information about a disk partition.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct PARTITION_INFORMATION_EX
        {
            /// <summary>
            /// The format of the partition. For a list of values, see PARTITION_STYLE.
            /// </summary>
            [FieldOffset(0)] public PARTITION_STYLE PartitionStyle;

            /// <summary>
            /// The starting offset of the partition.
            /// </summary>
            [FieldOffset(8)] public Int64 StartingOffset;

            /// <summary>
            /// The length of the partition, in bytes.
            /// </summary>
            [FieldOffset(16)] public Int64 PartitionLength;

            /// <summary>
            /// The number of the partition (1-based).
            /// </summary>
            [FieldOffset(24)] public uint PartitionNumber;

            /// <summary>
            /// If this member is TRUE, the partition information has changed. When you change a partition (with 
            /// IOCTL_DISK_SET_DRIVE_LAYOUT), the system uses this member to determine which partitions have changed
            /// and need their information rewritten.
            /// </summary>
            [FieldOffset(28)] [MarshalAs(UnmanagedType.I1)]
            public bool RewritePartition;

            /// <summary>
            /// A PARTITION_INFORMATION_MBR structure that specifies partition information specific to master boot 
            /// record (MBR) disks. The MBR partition format is the standard AT-style format.
            /// </summary>
            [FieldOffset(32)] public PARTITION_INFORMATION_MBR Mbr;

            /// <summary>
            /// A PARTITION_INFORMATION_GPT structure that specifies partition information specific to GUID partition 
            /// table (GPT) disks. The GPT format corresponds to the EFI partition format.
            /// </summary>
            [FieldOffset(32)] public PARTITION_INFORMATION_GPT Gpt;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct DRIVE_LAYOUT_INFORMATION_UNION
        {
            [FieldOffset(0)] public DRIVE_LAYOUT_INFORMATION_MBR Mbr;

            [FieldOffset(0)] public DRIVE_LAYOUT_INFORMATION_GPT Gpt;
        }

        /// <summary>
        /// Contains extended information about a drive's partitions.
        /// </summary>
        [StructLayout(LayoutKind.Explicit)]
        public struct DRIVE_LAYOUT_INFORMATION_EX
        {
            /// <summary>
            /// The style of the partitions on the drive enumerated by the PARTITION_STYLE enumeration.
            /// </summary>
            [FieldOffset(0)] public PARTITION_STYLE PartitionStyle;

            /// <summary>
            /// The number of partitions on a drive.
            /// 
            /// On disks with the MBR layout, this value is always a multiple of 4. Any partitions that are unused have
            /// a partition type of PARTITION_ENTRY_UNUSED.
            /// </summary>
            [FieldOffset(4)] public uint PartitionCount;

            /// <summary>
            /// A DRIVE_LAYOUT_INFORMATION_MBR structure containing information about the master boot record type 
            /// partitioning on the drive.
            /// </summary>
            [FieldOffset(8)] public DRIVE_LAYOUT_INFORMATION_UNION Mbr;

            /// <summary>
            /// A DRIVE_LAYOUT_INFORMATION_GPT structure containing information about the GUID disk partition type 
            /// partitioning on the drive.
            /// </summary>
            [FieldOffset(8)] public DRIVE_LAYOUT_INFORMATION_GPT Gpt;

            /// <summary>
            /// A variable-sized array of PARTITION_INFORMATION_EX structures, one structure for each partition on the 
            /// drive.
            /// </summary>
            [FieldOffset(48)] [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 4)]
            public PARTITION_INFORMATION_EX[] PartitionEntry;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct CREATE_DISK_MBR
        {
            [FieldOffset(0)] public uint Signature;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct CREATE_DISK_GPT
        {
            [FieldOffset(0)] public Guid DiskId;

            [FieldOffset(16)] public uint MaxPartitionCount;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct CREATE_DISK
        {
            [FieldOffset(0)] public PARTITION_STYLE PartitionStyle;

            [FieldOffset(4)] public CREATE_DISK_MBR Mbr;

            [FieldOffset(4)] public CREATE_DISK_GPT Gpt;
        }

        public const int DRIVE_ACCESS_RETRIES = 10;
        public const int DRIVE_ACCESS_TIMEOUT = 15000;
        public const int MIN_EXTRA_PART_SIZE = 1024 * 1024;

        public class IoCtl /* constants */
        {
            public const UInt32
                DISK_BASE = 0x00000007,
                VOLUME_BASE = 0x00000056,
                STORAGE_BASE = 0x0000002d,
                FILE_DEVICE_DISK_SYSTEM = 0x00000008,
                FILE_DEVICE_FILE_SYSTEM = 0x00000009,
                METHOD_BUFFERED = 0,
                METHOD_IN_DIRECT = 1,
                METHOD_OUT_DIRECT = 2,
                METHOD_NEITHER = 3,
                FILE_READ_ACCESS = 0x0001,
                FILE_WRITE_ACCESS = 0x0002,
                FILE_ANY_ACCESS = 0;

            public const UInt32
                GENERIC_READ = 0x80000000,
                FILE_SHARE_WRITE = 0x2,
                FILE_SHARE_READ = 0x1,
                OPEN_EXISTING = 0x3;

            public static readonly UInt32 DISK_GET_DRIVE_LAYOUT_EX =
                IoCtl.CTL_CODE(DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 DISK_SET_DRIVE_LAYOUT_EX =
                IoCtl.CTL_CODE(DISK_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

            public static readonly UInt32 DISK_DELETE_DRIVE_LAYOUT =
                IoCtl.CTL_CODE(DISK_BASE, 0x0040, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

            public static readonly UInt32 DISK_CREATE_DISK =
                IoCtl.CTL_CODE(DISK_BASE, 0x0016, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

            public static readonly UInt32 DISK_UPDATE_PROPERTIES =
                IoCtl.CTL_CODE(DISK_BASE, 0x0050, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 DISK_GET_DRIVE_GEOMETRY_EX =
                IoCtl.CTL_CODE(DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 DISK_GET_DRIVE_GEOMETRY =
                IoCtl.CTL_CODE(DISK_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 FSCTL_ALLOW_EXTENDED_DASD_IO =
                IoCtl.CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER, FILE_ANY_ACCESS);

            public static readonly UInt32 FSCTL_LOCK_VOLUME =
                IoCtl.CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 FSCTL_UNLOCK_VOLUME =
                IoCtl.CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 FSCTL_DISMOUNT_VOLUME =
                IoCtl.CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 VOLUME_ONLINE =
                IoCtl.CTL_CODE(VOLUME_BASE, 2, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

            public static readonly UInt32 VOLUME_OFFLINE =
                IoCtl.CTL_CODE(VOLUME_BASE, 3, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

            public static readonly UInt32 VOLUME_GET_VOLUME_DISK_EXTENTS =
                IoCtl.CTL_CODE(VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static readonly UInt32 STORAGE_GET_DEVICE_NUMBER =
                IoCtl.CTL_CODE(STORAGE_BASE, 0x0420, METHOD_BUFFERED, FILE_ANY_ACCESS);

            public static UInt32 CTL_CODE(UInt32 DeviceType, UInt32 Function, UInt32 Method, UInt32 Access)
            {
                return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method));
            }
        }

        public class SafeHGlobalHandle : SafeHandle
        {
            public SafeHGlobalHandle(IntPtr handle) : base(IntPtr.Zero, true)
            {
                SetHandle(handle);
            }

            public override bool IsInvalid
            {
                get => handle == IntPtr.Zero;
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }
        #endregion


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

        [SuppressUnmanagedCodeSecurityAttribute]
        public sealed class SafeLocalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            public SafeLocalMemHandle(IntPtr existingHandle, bool ownsHandle) : base(ownsHandle)
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
