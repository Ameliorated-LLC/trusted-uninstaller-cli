using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Interprocess;

namespace TrustedUninstaller.Shared
{

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // This also works with CharSet.Ansi as long as the calling function uses the same character set.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    public class NativeProcess
    {
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessW(
            string lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int CREATE_NEW_CONSOLE = 0x00000010;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        const UInt32 INFINITE = 0xFFFFFFFF;
        const UInt32 WAIT_ABANDONED = 0x00000080;
        const UInt32 WAIT_OBJECT_0 = 0x00000000;
        const UInt32 WAIT_TIMEOUT = 0x00000102;

        [InterprocessMethod(Level.Administrator)]
        public static int StartProcessAsTI(string path, string arguments)
        {
            var controller = new ServiceController("TrustedInstaller");
            if (controller.Status != ServiceControllerStatus.Running)
            {
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running);
            }

            var targetProcess = Process.GetProcessesByName("TrustedInstaller").FirstOrDefault();
            if (targetProcess == null)
                throw new Exception("Could not find TrustedInstaller process.");

            var parent = targetProcess.Id;
            
            // Create a new process with a different parent process
            // https://stackoverflow.com/questions/10554913/how-to-call-createprocess-with-startupinfoex-from-c-sharp-and-re-parent-the-ch
            var pInfo = new PROCESS_INFORMATION();
            var sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
            var lpValue = IntPtr.Zero;

            try
            {
                var lpSize = IntPtr.Zero;
                var success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                if (success || lpSize == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                success = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                if (!success)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var parentHandle = Process.GetProcessById(parent).Handle;
                // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                success = UpdateProcThreadAttribute(
                    sInfoEx.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);
                if (!success)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                var pSec = new SECURITY_ATTRIBUTES();
                var tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);

                CreateProcessW(null,
                    $"\"{path}\"{(String.IsNullOrEmpty(arguments) ? null : " " + arguments)}",
                    ref pSec,
                    ref tSec,
                    false,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    null,
                    ref sInfoEx,
                    out pInfo);
                
                return pInfo.dwProcessId;
            }
            finally
            {
                // Free the attribute list
                if (sInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValue);

                // Close process and thread handles
                if (pInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hProcess);
                }
                if (pInfo.hThread != IntPtr.Zero)
                {
                    CloseHandle(pInfo.hThread);
                }
            }
        }
    }
}
