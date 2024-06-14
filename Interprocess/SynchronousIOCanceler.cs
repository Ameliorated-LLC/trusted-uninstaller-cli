using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace Interprocess
{
    public class SynchronousIoCanceler : IDisposable
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CancelSynchronousIo(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [Flags]
        public enum ThreadAccess
        {
            Terminate = 0x0001,
            SuspendResume = 0x0002,
            GetContext = 0x0008,
            SetContext = 0x0010,
            SetInformation = 0x0020,
            QueryInformation = 0x0040,
            SetThreadToken = 0x0080,
            Impersonate = 0x0100,
            DirectImpersonation = 0x0200,
            SetLimitedInformation = 0x0400,
            QueryLimitedInformation = 0x0800
        }

        private readonly IntPtr _thread;
        private Timer _cancelLoop;
        private CancellationTokenRegistration _registration;

        public SynchronousIoCanceler(CancellationToken token, int cancelInterval = 1000)
        {
            _thread = OpenThread(ThreadAccess.Terminate, false, GetCurrentThreadId());
            _registration = token.Register(() => _cancelLoop = new Timer(_ => { CancelSynchronousIo(_thread); }, null, 0, cancelInterval));
        }

        public SynchronousIoCanceler(int timeout, int cancelInterval = 1000)
        {
            _thread = OpenThread(ThreadAccess.Terminate, false, GetCurrentThreadId());
            _cancelLoop = new Timer(_ => { CancelSynchronousIo(_thread); }, null, timeout, cancelInterval);
        }

        public SynchronousIoCanceler(int timeout, CancellationToken token, int cancelInterval = 1000)
        {
            if (token == CancellationToken.None)
            {
                _thread = OpenThread(ThreadAccess.Terminate, false, GetCurrentThreadId());
                _cancelLoop = new Timer(_ => { CancelSynchronousIo(_thread); }, null, timeout, cancelInterval);
                return;
            }
            
            _thread = OpenThread(ThreadAccess.Terminate, false, GetCurrentThreadId());
            _cancelLoop = new Timer(_ => { CancelSynchronousIo(_thread); }, null, token.IsCancellationRequested ? 0 : timeout, cancelInterval);
            if (!token.IsCancellationRequested)
                _registration = token.Register(() => _cancelLoop.Change(0, cancelInterval));
        }
        
        public void Dispose()
        {
            _registration.Dispose();
            _cancelLoop?.Dispose();

            if (_thread != IntPtr.Zero)
                CloseHandle(_thread);
        }
    }
}