using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Collections.Specialized;
using System.Globalization;
using System.Security;
using System.Security.Permissions;
using System.Runtime.Versioning;
using System.Runtime.ConstrainedExecution;
using Microsoft.Win32;
using Core;

namespace TrustedUninstaller.Shared
{
    [DefaultEvent("Exited"), DefaultProperty("StartInfo"), HostProtection(SharedState = true, Synchronization = true, ExternalProcessMgmt = true, SelfAffectingProcessMgmt = true)]
    public static class AugmentedProcess
    {
        public class Process : Component
        {
            public enum CreateType {
                UserToken,
                RawToken
            }
            //
            // FIELDS
            //
            bool haveProcessId;
            int processId;
            bool haveProcessHandle;
            SafeProcessHandle m_processHandle;
            bool isRemoteMachine;
            string machineName;
            ProcessInfo processInfo;
            Int32 m_processAccess;
            ProcessThreadCollection threads;
            ProcessModuleCollection modules;
            bool haveMainWindow;
            IntPtr mainWindowHandle; // no need to use SafeHandle for window        
            string mainWindowTitle;
            bool haveWorkingSetLimits;
            bool haveProcessorAffinity;
            IntPtr processorAffinity;
            bool havePriorityClass;
            ProcessPriorityClass priorityClass;
            ProcessStartInfo startInfo;
            bool watchForExit;
            bool watchingForExit;
            EventHandler onExited;
            bool exited;
            int exitCode;
            bool signaled;
            DateTime exitTime;
            bool haveExitTime;
            bool responding;
            bool haveResponding;
            bool priorityBoostEnabled;
            bool havePriorityBoostEnabled;
            bool raisedOnExited;
            bool expandEnvironmentVariables;
            RegisteredWaitHandle registeredWaitHandle;
            WaitHandle waitHandle;
            ISynchronizeInvoke synchronizingObject;
            StreamReader standardOutput;
            StreamWriter standardInput;
            StreamReader standardError;
            OperatingSystem operatingSystem;
            bool disposed;
            static object s_CreateProcessLock = new object();

            // This enum defines the operation mode for redirected process stream.
            // We don't support switching between synchronous mode and asynchronous mode.
            private enum StreamReadMode
            {
                undefined,
                syncMode,
                asyncMode
            }

            StreamReadMode outputStreamReadMode;
            StreamReadMode errorStreamReadMode;
            public event DataReceivedEventHandler OutputDataReceived;
            public event DataReceivedEventHandler ErrorDataReceived;
            // Abstract the stream details
            internal AsyncStreamReader output;
            internal AsyncStreamReader error;
            internal bool pendingOutputRead;
            internal bool pendingErrorRead;
            internal static TraceSwitch processTracing = null;
            public Process()
            {
                this.machineName = ".";
                this.outputStreamReadMode = StreamReadMode.undefined;
                this.errorStreamReadMode = StreamReadMode.undefined;
                this.m_processAccess = NativeMethods.PROCESS_ALL_ACCESS;
            }
            [ResourceExposure(ResourceScope.Machine)]
            Process(string machineName, bool isRemoteMachine, int processId, ProcessInfo processInfo) : base()
            {
                this.processInfo = processInfo;
                this.machineName = machineName;
                this.isRemoteMachine = isRemoteMachine;
                this.processId = processId;
                this.haveProcessId = true;
                this.outputStreamReadMode = StreamReadMode.undefined;
                this.errorStreamReadMode = StreamReadMode.undefined;
                this.m_processAccess = NativeMethods.PROCESS_ALL_ACCESS;
            }

            //
            // PROPERTIES
            //
            bool Associated
            {
                get
                {
                    return haveProcessId || haveProcessHandle;
                }
            }
            
            public string ProcessName
            {
                get
                {
                    this.EnsureState(Process.State.HaveProcessInfo);
                    return this.processInfo.processName;
                }
            }
            
            public int ExitCode
            {
                get
                {
                    EnsureState(State.Exited);
                    return exitCode;
                }
            }
            public bool HasExited
            {
                get
                {
                    if (!exited)
                    {
                        EnsureState(State.Associated);
                        SafeProcessHandle handle = null;
                        try
                        {
                            handle = GetProcessHandle(NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.SYNCHRONIZE, false);
                            if (handle.IsInvalid)
                            {
                                exited = true;
                            }
                            else
                            {
                                int exitCode;

                                // Although this is the wrong way to check whether the process has exited,
                                // it was historically the way we checked for it, and a lot of code then took a dependency on
                                // the fact that this would always be set before the pipes were closed, so they would read
                                // the exit code out after calling ReadToEnd() or standard output or standard error. In order
                                // to allow 259 to function as a valid exit code and to break as few people as possible that
                                // took the ReadToEnd dependency, we check for an exit code before doing the more correct
                                // check to see if we have been signalled.
                                if (NativeMethods.GetExitCodeProcess(handle, out exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
                                {
                                    this.exited = true;
                                    this.exitCode = exitCode;
                                }
                                else
                                {
                                    // The best check for exit is that the kernel process object handle is invalid, 
                                    // or that it is valid and signaled.  Checking if the exit code != STILL_ACTIVE 
                                    // does not guarantee the process is closed,
                                    // since some process could return an actual STILL_ACTIVE exit code (259).
                                    if (!signaled) // if we just came from WaitForExit, don't repeat
                                    {
                                        ProcessWaitHandle wh = null;
                                        try
                                        {
                                            wh = new ProcessWaitHandle(handle);
                                            this.signaled = wh.WaitOne(0, false);
                                        }
                                        finally
                                        {
                                            if (wh != null) wh.Close();
                                        }
                                    }
                                    if (signaled)
                                    {
                                        if (!NativeMethods.GetExitCodeProcess(handle, out exitCode)) throw new Win32Exception();
                                        this.exited = true;
                                        this.exitCode = exitCode;
                                    }
                                }
                            }
                        }
                        finally
                        {
                            ReleaseProcessHandle(handle);
                        }
                        if (exited)
                        {
                            RaiseOnExited();
                        }
                    }
                    return exited;
                }
            }
            public IntPtr Handle
            {
                [ResourceExposure(ResourceScope.Machine)]
                [ResourceConsumption(ResourceScope.Machine)]
                get
                {
                    EnsureState(State.Associated);
                    return OpenProcessHandle(this.m_processAccess).DangerousGetHandle();
                }
            }
            [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
            public SafeProcessHandle SafeHandle
            {
                get
                {
                    EnsureState(State.Associated);
                    return OpenProcessHandle(this.m_processAccess);
                }
            }
            public int Id
            {
                get
                {
                    EnsureState(State.HaveId);
                    return processId;
                }
            }
            public string MachineName
            {
                get
                {
                    EnsureState(State.Associated);
                    return machineName;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long NonpagedSystemMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.poolNonpagedBytes;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PagedMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.pageFileBytes;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PagedSystemMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.poolPagedBytes;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PeakPagedMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.pageFileBytesPeak;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PeakWorkingSet64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.workingSetPeak;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PeakVirtualMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.virtualBytesPeak;
                }
            }
            private OperatingSystem OperatingSystem
            {
                get
                {
                    if (operatingSystem == null)
                    {
                        operatingSystem = Environment.OSVersion;
                    }
                    return operatingSystem;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long PrivateMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.privateBytes;
                }
            }
            public int SessionId
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.sessionId;
                }
            }
            public ProcessStartInfo StartInfo
            {
                get
                {
                    return startInfo;
                }
                [ResourceExposure(ResourceScope.Machine)]
                set
                {
                    if (value == null)
                    {
                        throw new ArgumentNullException("value");
                    }
                    startInfo = value;
                }
            }
            
            public bool ExpandEnvironmentVariables
            {
                get
                {
                    return expandEnvironmentVariables;
                }
                set
                {
                    expandEnvironmentVariables = value;
                }
            }
            
            public ISynchronizeInvoke SynchronizingObject
            {
                get
                {
                    if (this.synchronizingObject == null && DesignMode)
                    {
                        IDesignerHost host = (IDesignerHost)GetService(typeof(IDesignerHost));
                        if (host != null)
                        {
                            object baseComponent = host.RootComponent;
                            if (baseComponent != null && baseComponent is ISynchronizeInvoke) this.synchronizingObject = (ISynchronizeInvoke)baseComponent;
                        }
                    }
                    return this.synchronizingObject;
                }
                set
                {
                    this.synchronizingObject = value;
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long VirtualMemorySize64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.virtualBytes;
                }
            }
            public bool EnableRaisingEvents
            {
                get
                {
                    return watchForExit;
                }
                set
                {
                    if (value != watchForExit)
                    {
                        if (Associated)
                        {
                            if (value)
                            {
                                OpenProcessHandle();
                                EnsureWatchingForExit();
                            }
                            else
                            {
                                StopWatchingForExit();
                            }
                        }
                        watchForExit = value;
                    }
                }
            }
            public StreamWriter StandardInput
            {
                get
                {
                    if (standardInput == null)
                    {
                        throw new InvalidOperationException("CantGetStandardIn");
                    }
                    return standardInput;
                }
            }
            public StreamReader StandardOutput
            {
                get
                {
                    if (standardOutput == null)
                    {
                        throw new InvalidOperationException("CantGetStandardOut");
                    }
                    if (outputStreamReadMode == StreamReadMode.undefined)
                    {
                        outputStreamReadMode = StreamReadMode.syncMode;
                    }
                    else if (outputStreamReadMode != StreamReadMode.syncMode)
                    {
                        throw new InvalidOperationException("CantMixSyncAsyncOperation");
                    }
                    return standardOutput;
                }
            }
            public StreamReader StandardError
            {
                get
                {
                    if (standardError == null)
                    {
                        throw new InvalidOperationException("CantGetStandardError");
                    }
                    if (errorStreamReadMode == StreamReadMode.undefined)
                    {
                        errorStreamReadMode = StreamReadMode.syncMode;
                    }
                    else if (errorStreamReadMode != StreamReadMode.syncMode)
                    {
                        throw new InvalidOperationException("CantMixSyncAsyncOperation");
                    }
                    return standardError;
                }
            }
            public int WorkingSet
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return unchecked((int)processInfo.workingSet);
                }
            }
            [System.Runtime.InteropServices.ComVisible(false)]
            public long WorkingSet64
            {
                get
                {
                    EnsureState(State.HaveNtProcessInfo);
                    return processInfo.workingSet;
                }
            }
            public event EventHandler Exited
            {
                add
                {
                    onExited += value;
                }
                remove
                {
                    onExited -= value;
                }
            }
            /// <devdoc>
            ///     Release the temporary handle we used to get process information.
            ///     If we used the process handle stored in the process object (we have all access to the handle,) don't release it.
            /// </devdoc>
            /// <internalonly/>
            void ReleaseProcessHandle(SafeProcessHandle handle)
            {
                if (handle == null)
                {
                    return;
                }
                if (haveProcessHandle && handle == m_processHandle)
                {
                    return;
                }
                handle.Close();
            }
            /// <devdoc>
            ///     This is called from the threadpool when a proces exits.
            /// </devdoc>
            /// <internalonly/>
            private void CompletionCallback(object context, bool wasSignaled)
            {
                StopWatchingForExit();
                RaiseOnExited();
            }
            /// <internalonly/>
            /// <devdoc>
            ///    <para>
            ///       Free any resources associated with this component.
            ///    </para>
            /// </devdoc>
            protected override void Dispose(bool disposing)
            {
                if (!disposed)
                {
                    if (disposing)
                    {
                        //Dispose managed and unmanaged resources
                        Close();
                    }
                    this.disposed = true;
                    base.Dispose(disposing);
                }
            }
            /// <devdoc>
            ///    <para>
            ///       Frees any resources associated with this component.
            ///    </para>
            /// </devdoc>
            public void Close()
            {
                if (Associated)
                {
                    if (haveProcessHandle)
                    {
                        StopWatchingForExit();
                        m_processHandle.Close();
                        m_processHandle = null;
                        haveProcessHandle = false;
                    }
                    haveProcessId = false;
                    isRemoteMachine = false;
                    machineName = ".";
                    raisedOnExited = false;

                    //Don't call close on the Readers and writers
                    //since they might be referenced by somebody else while the 
                    //process is still alive but this method called.
                    standardOutput = null;
                    standardInput = null;
                    standardError = null;
                    output = null;
                    error = null;
                    Refresh();
                }
            }
            /// <devdoc>
            ///     Helper method for checking preconditions when accessing properties.
            /// </devdoc>
            /// <internalonly/>
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            void EnsureState(State state)
            {
                if ((state & State.Associated) != (State)0)
                    if (!Associated)
                        throw new InvalidOperationException("NoAssociatedProcess");
                if ((state & State.IsLocal) != (State)0 && isRemoteMachine)
                {
                    throw new NotSupportedException("NotSupportedRemote");
                }
                if ((state & Process.State.HaveProcessInfo) != (Process.State) 0 && this.processInfo == null)
                {
                    if ((state & Process.State.HaveId) == (Process.State) 0)
                        this.EnsureState(Process.State.HaveId);
                    this.processInfo = GetProcessInfo(this.processId, this.machineName);
                    if (this.processInfo == null)
                        throw new InvalidOperationException("NoProcessInfo");
                }
                if ((state & State.Exited) != (State)0)
                {
                    if (!HasExited)
                    {
                        throw new InvalidOperationException("WaitTillExit");
                    }
                    if (!haveProcessHandle)
                    {
                        throw new InvalidOperationException("NoProcessHandle");
                    }
                }
            }
            void EnsureWatchingForExit()
            {
                if (!watchingForExit)
                {
                    lock (this)
                    {
                        if (!watchingForExit)
                        {
                            watchingForExit = true;
                            try
                            {
                                this.waitHandle = new ProcessWaitHandle(m_processHandle);
                                this.registeredWaitHandle = ThreadPool.RegisterWaitForSingleObject(this.waitHandle, new WaitOrTimerCallback(this.CompletionCallback), null, -1, true);
                            }
                            catch
                            {
                                watchingForExit = false;
                                throw;
                            }
                        }
                    }
                }
            }
            protected void OnExited()
            {
                EventHandler exited = onExited;
                if (exited != null)
                {
                    if (this.SynchronizingObject != null && this.SynchronizingObject.InvokeRequired)
                        this.SynchronizingObject.BeginInvoke(exited, new object[]
                        {
                            this, EventArgs.Empty
                        });
                    else exited(this, EventArgs.Empty);
                }
            }
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            SafeProcessHandle GetProcessHandle(int access, bool throwIfExited)
            {
                if (haveProcessHandle)
                {
                    if (throwIfExited)
                    {
                        // Since haveProcessHandle is true, we know we have the process handle
                        // open with at least SYNCHRONIZE access, so we can wait on it with 
                        // zero timeout to see if the process has exited.
                        ProcessWaitHandle waitHandle = null;
                        try
                        {
                            waitHandle = new ProcessWaitHandle(m_processHandle);
                            if (waitHandle.WaitOne(0, false))
                            {
                                if (haveProcessId) throw new InvalidOperationException("Process has exited: " + processId);
                                else throw new InvalidOperationException("ProcessHasExitedNoId");
                            }
                        }
                        finally
                        {
                            if (waitHandle != null)
                            {
                                waitHandle.Close();
                            }
                        }
                    }
                    return m_processHandle;
                }
                else
                {
                    throw new Exception("(AME) Process handle not available.");
                }
            }
            /// <devdoc>
            ///     Gets a short-term handle to the process, with the given access.  If a handle exists,
            ///     then it is reused.  If the process has exited, it throws an exception.
            /// </devdoc>
            /// <internalonly/>
            SafeProcessHandle GetProcessHandle(int access)
            {
                return GetProcessHandle(access, true);
            }
            /// <devdoc>
            ///     Opens a long-term handle to the process, with all access.  If a handle exists,
            ///     then it is reused.  If the process has exited, it throws an exception.
            /// </devdoc>
            /// <internalonly/>
            SafeProcessHandle OpenProcessHandle()
            {
                return OpenProcessHandle(NativeMethods.PROCESS_ALL_ACCESS);
            }
            SafeProcessHandle OpenProcessHandle(Int32 access)
            {
                if (!haveProcessHandle)
                {
                    //Cannot open a new process handle if the object has been disposed, since finalization has been suppressed.            
                    if (this.disposed)
                    {
                        throw new ObjectDisposedException(GetType().Name);
                    }
                    SetProcessHandle(GetProcessHandle(access));
                }
                return m_processHandle;
            }
            /// <devdoc>
            ///     Raise the Exited event, but make sure we don't do it more than once.
            /// </devdoc>
            /// <internalonly/>
            void RaiseOnExited()
            {
                if (!raisedOnExited)
                {
                    lock (this)
                    {
                        if (!raisedOnExited)
                        {
                            raisedOnExited = true;
                            OnExited();
                        }
                    }
                }
            }
            /// <devdoc>
            ///    <para>
            ///       Discards any information about the associated process
            ///       that has been cached inside the process component. After <see cref='System.Diagnostics.Process.Refresh'/> is called, the
            ///       first request for information for each property causes the process component
            ///       to obtain a new value from the associated process.
            ///    </para>
            /// </devdoc>
            public void Refresh()
            {
                processInfo = null;
                threads = null;
                modules = null;
                mainWindowTitle = null;
                exited = false;
                signaled = false;
                haveMainWindow = false;
                haveWorkingSetLimits = false;
                haveProcessorAffinity = false;
                havePriorityClass = false;
                haveExitTime = false;
                haveResponding = false;
                havePriorityBoostEnabled = false;
            }
            /// <devdoc>
            ///     Helper to associate a process handle with this component.
            /// </devdoc>
            /// <internalonly/>
            void SetProcessHandle(SafeProcessHandle processHandle)
            {
                this.m_processHandle = processHandle;
                this.haveProcessHandle = true;
                if (watchForExit)
                {
                    EnsureWatchingForExit();
                }
            }
            /// <devdoc>
            ///     Helper to associate a process id with this component.
            /// </devdoc>
            /// <internalonly/>
            [ResourceExposure(ResourceScope.Machine)]
            void SetProcessId(int processId)
            {
                this.processId = processId;
                this.haveProcessId = true;
            }
            /// <devdoc>
            ///    <para>
            ///       Starts a process specified by the <see cref='System.Diagnostics.Process.StartInfo'/> property of this <see cref='System.Diagnostics.Process'/>
            ///       component and associates it with the
            ///    <see cref='System.Diagnostics.Process'/> . If a process resource is reused 
            ///       rather than started, the reused process is associated with this <see cref='System.Diagnostics.Process'/>
            ///       component.
            ///    </para>
            /// </devdoc>
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            public bool Start(CreateType type, ref Win32.TokensEx.SafeTokenHandle token)
            {
                Close();
                ProcessStartInfo startInfo = StartInfo;
                if (startInfo.FileName.Length == 0) throw new InvalidOperationException("FileNameMissing");

                return StartWithCreateProcess(startInfo, type, ref token);
            }
            [ResourceExposure(ResourceScope.Process)]
            [ResourceConsumption(ResourceScope.Process)]
            private static void CreatePipeWithSecurityAttributes(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, NativeMethods.SECURITY_ATTRIBUTES lpPipeAttributes, int nSize)
            {
                bool ret = NativeMethods.CreatePipe(out hReadPipe, out hWritePipe, lpPipeAttributes, nSize);
                if (!ret || hReadPipe.IsInvalid || hWritePipe.IsInvalid)
                {
                    throw new Win32Exception();
                }
            }

            // Using synchronous Anonymous pipes for process input/output redirection means we would end up 
            // wasting a worker threadpool thread per pipe instance. Overlapped pipe IO is desirable, since 
            // it will take advantage of the NT IO completion port infrastructure. But we can't really use 
            // Overlapped I/O for process input/output as it would break Console apps (managed Console class 
            // methods such as WriteLine as well as native CRT functions like printf) which are making an
            // assumption that the console standard handles (obtained via GetStdHandle()) are opened
            // for synchronous I/O and hence they can work fine with ReadFile/WriteFile synchrnously!
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            private void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle, bool parentInputs)
            {
                NativeMethods.SECURITY_ATTRIBUTES securityAttributesParent = new NativeMethods.SECURITY_ATTRIBUTES();
                securityAttributesParent.bInheritHandle = true;
                SafeFileHandle hTmp = null;
                try
                {
                    if (parentInputs)
                    {
                        CreatePipeWithSecurityAttributes(out childHandle, out hTmp, securityAttributesParent, 0);
                    }
                    else
                    {
                        CreatePipeWithSecurityAttributes(out hTmp, out childHandle, securityAttributesParent, 0);
                    }
                    // Duplicate the parent handle to be non-inheritable so that the child process 
                    // doesn't have access. This is done for correctness sake, exact reason is unclear.
                    // One potential theory is that child process can do something brain dead like 
                    // closing the parent end of the pipe and there by getting into a blocking situation
                    // as parent will not be draining the pipe at the other end anymore. 
                    if (!NativeMethods.DuplicateHandle(new HandleRef(this, NativeMethods.GetCurrentProcess()), hTmp, new HandleRef(this, NativeMethods.GetCurrentProcess()), out parentHandle, 0, false,
                            NativeMethods.DUPLICATE_SAME_ACCESS))
                    {
                        throw new Win32Exception();
                    }
                }
                finally
                {
                    if (hTmp != null && !hTmp.IsInvalid)
                    {
                        hTmp.Close();
                    }
                }
            }
            private static StringBuilder BuildCommandLine(string executableFileName, string arguments)
            {
                // Construct a StringBuilder with the appropriate command line
                // to pass to CreateProcess.  If the filename isn't already 
                // in quotes, we quote it here.  This prevents some security
                // problems (it specifies exactly which part of the string
                // is the file to execute).
                StringBuilder commandLine = new StringBuilder();
                string fileName = executableFileName.Trim();
                bool fileNameIsQuoted = (fileName.StartsWith("\"", StringComparison.Ordinal) && fileName.EndsWith("\"", StringComparison.Ordinal));
                if (!fileNameIsQuoted)
                {
                    commandLine.Append("\"");
                }
                commandLine.Append(fileName);
                if (!fileNameIsQuoted)
                {
                    commandLine.Append("\"");
                }
                if (!String.IsNullOrEmpty(arguments))
                {
                    commandLine.Append(" ");
                    commandLine.Append(arguments);
                }
                return commandLine;
            }
            [ResourceExposure(ResourceScope.Machine)]
            [ResourceConsumption(ResourceScope.Machine)]
            private bool StartWithCreateProcess(ProcessStartInfo startInfo, CreateType type, ref Win32.TokensEx.SafeTokenHandle token)
            {
                // See knowledge base article Q190351 for an explanation of the following code.  Noteworthy tricky points:
                //    * The handles are duplicated as non-inheritable before they are passed to CreateProcess so
                //      that the child process can not close them
                //    * CreateProcess allows you to redirect all or none of the standard IO handles, so we use
                //      GetStdHandle for the handles that are not being redirected

                //Cannot start a new process and store its handle if the object has been disposed, since finalization has been suppressed.            
                if (this.disposed)
                {
                    throw new ObjectDisposedException(GetType().Name);
                }
                StringBuilder commandLine = BuildCommandLine(startInfo.FileName, startInfo.Arguments);
                NativeMethods.STARTUPINFO startupInfo = new NativeMethods.STARTUPINFO();
                NativeMethods.PROCESS_INFORMATION processInfo = new NativeMethods.PROCESS_INFORMATION();
                SafeProcessHandle procSH = new SafeProcessHandle();
                SafeThreadHandle threadSH = new SafeThreadHandle();
                bool retVal;
                int errorCode = 0;
                // handles used in parent process
                SafeFileHandle standardInputWritePipeHandle = null;
                SafeFileHandle standardOutputReadPipeHandle = null;
                SafeFileHandle standardErrorReadPipeHandle = null;
                IntPtr environmentPtr = (IntPtr)0;
                //GCHandle environmentHandle = new GCHandle();
                lock (s_CreateProcessLock)
                {
                    try
                    {
                        // set up the streams
                        if (startInfo.CreateNoWindow && (startInfo.RedirectStandardInput || startInfo.RedirectStandardOutput || startInfo.RedirectStandardError))
                        {
                            if (startInfo.StandardOutputEncoding != null && !startInfo.RedirectStandardOutput)
                            {
                                throw new InvalidOperationException("StandardOutputEncodingNotAllowed");
                            }
                            if (startInfo.StandardErrorEncoding != null && !startInfo.RedirectStandardError)
                            {
                                throw new InvalidOperationException("StandardErrorEncodingNotAllowed");
                            }
                            
                            if (startInfo.RedirectStandardInput)
                            {
                                CreatePipe(out standardInputWritePipeHandle, out startupInfo.hStdInput, true);
                            }
                            else
                            {
                                startupInfo.hStdInput = new SafeFileHandle(NativeMethods.GetStdHandle(NativeMethods.STD_INPUT_HANDLE), false);
                            }
                            if (startInfo.RedirectStandardOutput)
                            {
                                CreatePipe(out standardOutputReadPipeHandle, out startupInfo.hStdOutput, false);
                            }
                            else
                            {
                                startupInfo.hStdOutput = new SafeFileHandle(NativeMethods.GetStdHandle(NativeMethods.STD_OUTPUT_HANDLE), false);
                            }
                            if (startInfo.RedirectStandardError)
                            {
                                CreatePipe(out standardErrorReadPipeHandle, out startupInfo.hStdError, false);
                            }
                            else
                            {
                                startupInfo.hStdError = new SafeFileHandle(NativeMethods.GetStdHandle(NativeMethods.STD_ERROR_HANDLE), false);
                            }
                            startupInfo.dwFlags = NativeMethods.STARTF_USESTDHANDLES;
                        }

                        // set up the creation flags paramater
                        int creationFlags = 0;
                        if (startInfo.CreateNoWindow) creationFlags |= NativeMethods.CREATE_NO_WINDOW;

                        // set up the environment block parameterhttps://www.beyondtrust.com/assets/documents/BeyondTrust-Microsoft-Vulnerabilities-Report-2021.pdf
                        
                        //if (startInfo.environmentVariables != null)
                        if (true)
                        {
                            creationFlags |= NativeMethods.CREATE_UNICODE_ENVIRONMENT;
                            //byte[] environmentBytes = EnvironmentBlock.ToByteArray(startInfo.environmentVariables, true);
                            //environmentHandle = GCHandle.Alloc(environmentBytes, GCHandleType.Pinned);
                            //environmentPtr = environmentHandle.AddrOfPinnedObject();
                            Win32.Process.CreateEnvironmentBlock(out environmentPtr, token, false);
                        }

                        /*
                        if (ExpandEnvironmentVariables && startInfo.Arguments.Contains("%"))
                        {
                            Environment.ExpandEnvironmentVariables()
                            var envVars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                            IntPtr next = environmentPtr;
                            while (Marshal.ReadByte(next) != 0)
                            {
                                var str = Marshal.PtrToStringUni(next);
                                // skip first character because windows allows env vars to begin with equal sign
                                var splitPoint = str.IndexOf('=', 1);
                                var envVarName = str.Substring(0, splitPoint);
                                var envVarVal = str.Substring(splitPoint + 1);
                                envVars.Add(envVarName, envVarVal);
                                next = (IntPtr)((Int64)next + (str.Length * 2) + 2);
                            }
                            return envVars;
                        }
                        */

                        if (!startInfo.CreateNoWindow)
                        {
                            creationFlags |= (int)Win32.Process.ProcessCreationFlags.CREATE_DEFAULT_ERROR_MODE;
                            creationFlags |= (int)Win32.Process.ProcessCreationFlags.CREATE_NEW_CONSOLE;
                            creationFlags |= (int)Win32.Process.ProcessCreationFlags.CREATE_NEW_PROCESS_GROUP;
                            //startupInfo.lpDesktop = "Winsta0\\Default";
                        }
                        
                        string workingDirectory = startInfo.WorkingDirectory;
                        if (workingDirectory == string.Empty) workingDirectory = Environment.CurrentDirectory;
                        RuntimeHelpers.PrepareConstrainedRegions();
                        try { }
                        finally
                        {
                            retVal = false;
                            if (type == CreateType.UserToken)
                            {
                                retVal = NativeMethods.CreateProcessAsUser(token,
                                    null, // we don't need this since all the info is in commandLine
                                    commandLine, // pointer to the command line string
                                    null, // pointer to process security attributes, we don't need to inheriat the handle
                                    null, // pointer to thread security attributes
                                    true, // handle inheritance flag
                                    creationFlags, // creation flags
                                    environmentPtr, // pointer to new environment block
                                    workingDirectory, // pointer to current directory name
                                    startupInfo, // pointer to STARTUPINFO
                                    processInfo // pointer to PROCESS_INFORMATION
                                );
                            } else if (type == CreateType.RawToken)
                            {
                                retVal = NativeMethods.CreateProcessWithToken(token,
                                    NativeMethods.LogonFlags.LOGON_WITH_PROFILE,
                                    null, // we don't need this since all the info is in commandLine
                                    commandLine, // pointer to the command line string
                                    creationFlags, // creation flags
                                    environmentPtr, // pointer to new environment block
                                    workingDirectory, // pointer to current directory name
                                    startupInfo, // pointer to STARTUPINFO
                                    processInfo // pointer to PROCESS_INFORMATION
                                );
                            }
                            /*
                            retVal = NativeMethods.CreateProcess(null, // we don't need this since all the info is in commandLine
                                commandLine, // pointer to the command line string
                                null, // pointer to process security attributes, we don't need to inheriat the handle
                                null, // pointer to thread security attributes
                                true, // handle inheritance flag
                                creationFlags, // creation flags
                                environmentPtr, // pointer to new environment block
                                workingDirectory, // pointer to current directory name
                                startupInfo, // pointer to STARTUPINFO
                                processInfo // pointer to PROCESS_INFORMATION
                            );
                            */
                            if (!retVal) errorCode = Marshal.GetLastWin32Error();
                            if (processInfo.hProcess != (IntPtr)0 && processInfo.hProcess != (IntPtr)NativeMethods.INVALID_HANDLE_VALUE) procSH.InitialSetHandle(processInfo.hProcess);
                            if (processInfo.hThread != (IntPtr)0 && processInfo.hThread != (IntPtr)NativeMethods.INVALID_HANDLE_VALUE) threadSH.InitialSetHandle(processInfo.hThread);
                        }
                        if (!retVal)
                        {
                            if (errorCode == NativeMethods.ERROR_BAD_EXE_FORMAT || errorCode == NativeMethods.ERROR_EXE_MACHINE_TYPE_MISMATCH)
                            {
                                throw new Win32Exception(errorCode, "InvalidApplication");
                            }
                            throw new Win32Exception(errorCode);
                        }
                    }
                    finally
                    {
                        // free environment block
                        //if (environmentHandle.IsAllocated)
                        //{
                           // environmentHandle.Free();
                        //}
                        Win32.Process.DestroyEnvironmentBlock(environmentPtr);
                        startupInfo.Dispose();
                    }
                }
                if (startInfo.RedirectStandardInput)
                {
                    standardInput = new StreamWriter(new FileStream(standardInputWritePipeHandle, FileAccess.Write, 4096, false), Console.InputEncoding, 4096);
                    standardInput.AutoFlush = true;
                }
                if (startInfo.RedirectStandardOutput)
                {
                    Encoding enc = (startInfo.StandardOutputEncoding != null) ? startInfo.StandardOutputEncoding : Console.OutputEncoding;
                    standardOutput = new StreamReader(new FileStream(standardOutputReadPipeHandle, FileAccess.Read, 4096, false), enc, true, 4096);
                }
                if (startInfo.RedirectStandardError)
                {
                    Encoding enc = (startInfo.StandardErrorEncoding != null) ? startInfo.StandardErrorEncoding : Console.OutputEncoding;
                    standardError = new StreamReader(new FileStream(standardErrorReadPipeHandle, FileAccess.Read, 4096, false), enc, true, 4096);
                }
                bool ret = false;
                if (!procSH.IsInvalid)
                {
                    SetProcessHandle(procSH);
                    SetProcessId(processInfo.dwProcessId);
                    threadSH.Close();
                    ret = true;
                }
                return ret;
            }

/*
            private static string ExpandEnvironmentVariables(string name, Dictionary<string, string> environment)
            {

                switch (name)
                {
                    case null:
                    case "":
                        return name;
                    default:
                        environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            {"SuSSY", "gussys"},
                            {"AMoGus", "gussys"},
                            {"Sussex", "gussys"}
                        };

                        StringBuilder result = new StringBuilder();

                        int index = name.IndexOf('%');
                        if (index > 0)
                            result.Append(name.Substring(index));

                        int lastValidIndex = -1;
                        while (index != -1)
                        {
                            lastValidIndex = index;

                            var end = name.IndexOf('%', index + 1);
                            if (end == -1)
                            {
                                result.Append('%');
                                break;
                            }

                            // Double % escape
                            if (end == index + 1)
                            {
                                index = name.IndexOf('%', index + 2);
                                result.Append(index == -1 ? "%" : "%" +  name.Substring(end + 1, index - (end + 1)));
                                continue;
                            }

                            lastValidIndex = end;

                            if (environment.TryGetValue(name.Substring(index + 1, end - (index + 1)), out string varValue))
                                result.Append(varValue);

                            index = name.IndexOf('%', end + 1);

                            if (index != -1)
                            {
                                result.Append(name.Substring(end + 1, index - (end + 1)));
                            }
                        }

                        result.Append(lastValidIndex != -1 ? name.Substring(index + 1, name.Length - (index + 1)) : name);

                        return result.ToString();
                }
                
            }
            */
            [ResourceExposure(ResourceScope.Machine)]
            [ResourceConsumption(ResourceScope.Machine)]
            private bool StartWithShellExecuteEx(ProcessStartInfo startInfo)
            {
                //Cannot start a new process and store its handle if the object has been disposed, since finalization has been suppressed.            
                if (this.disposed) throw new ObjectDisposedException(GetType().Name);
                if (!String.IsNullOrEmpty(startInfo.UserName) || (startInfo.Password != null))
                {
                    throw new InvalidOperationException("CantStartAsUser");
                }
                if (startInfo.RedirectStandardInput || startInfo.RedirectStandardOutput || startInfo.RedirectStandardError)
                {
                    throw new InvalidOperationException("CantRedirectStreams");
                }
                if (startInfo.StandardErrorEncoding != null)
                {
                    throw new InvalidOperationException("StandardErrorEncodingNotAllowed");
                }
                if (startInfo.StandardOutputEncoding != null)
                {
                    throw new InvalidOperationException("StandardOutputEncodingNotAllowed");
                }

                // can't set env vars with ShellExecuteEx...
                if (startInfo.environmentVariables != null)
                {
                    throw new InvalidOperationException("CantUseEnvVars");
                }
                NativeMethods.ShellExecuteInfo shellExecuteInfo = new NativeMethods.ShellExecuteInfo();
                shellExecuteInfo.fMask = NativeMethods.SEE_MASK_NOCLOSEPROCESS;
                if (startInfo.ErrorDialog)
                {
                    shellExecuteInfo.hwnd = startInfo.ErrorDialogParentHandle;
                }
                else
                {
                    shellExecuteInfo.fMask |= NativeMethods.SEE_MASK_FLAG_NO_UI;
                }
                switch (startInfo.WindowStyle)
                {
                    case ProcessWindowStyle.Hidden:
                        shellExecuteInfo.nShow = NativeMethods.SW_HIDE;
                        break;
                    case ProcessWindowStyle.Minimized:
                        shellExecuteInfo.nShow = NativeMethods.SW_SHOWMINIMIZED;
                        break;
                    case ProcessWindowStyle.Maximized:
                        shellExecuteInfo.nShow = NativeMethods.SW_SHOWMAXIMIZED;
                        break;
                    default:
                        shellExecuteInfo.nShow = NativeMethods.SW_SHOWNORMAL;
                        break;
                }
                try
                {
                    if (startInfo.FileName.Length != 0) shellExecuteInfo.lpFile = Marshal.StringToHGlobalAuto(startInfo.FileName);
                    if (startInfo.Verb.Length != 0) shellExecuteInfo.lpVerb = Marshal.StringToHGlobalAuto(startInfo.Verb);
                    if (startInfo.Arguments.Length != 0) shellExecuteInfo.lpParameters = Marshal.StringToHGlobalAuto(startInfo.Arguments);
                    if (startInfo.WorkingDirectory.Length != 0) shellExecuteInfo.lpDirectory = Marshal.StringToHGlobalAuto(startInfo.WorkingDirectory);
                    shellExecuteInfo.fMask |= NativeMethods.SEE_MASK_FLAG_DDEWAIT;
                    ShellExecuteHelper executeHelper = new ShellExecuteHelper(shellExecuteInfo);
                    if (!executeHelper.ShellExecuteOnSTAThread())
                    {
                        int error = executeHelper.ErrorCode;
                        if (error == 0)
                        {
                            switch ((long)shellExecuteInfo.hInstApp)
                            {
                                case NativeMethods.SE_ERR_FNF:
                                    error = NativeMethods.ERROR_FILE_NOT_FOUND;
                                    break;
                                case NativeMethods.SE_ERR_PNF:
                                    error = NativeMethods.ERROR_PATH_NOT_FOUND;
                                    break;
                                case NativeMethods.SE_ERR_ACCESSDENIED:
                                    error = NativeMethods.ERROR_ACCESS_DENIED;
                                    break;
                                case NativeMethods.SE_ERR_OOM:
                                    error = NativeMethods.ERROR_NOT_ENOUGH_MEMORY;
                                    break;
                                case NativeMethods.SE_ERR_DDEFAIL:
                                case NativeMethods.SE_ERR_DDEBUSY:
                                case NativeMethods.SE_ERR_DDETIMEOUT:
                                    error = NativeMethods.ERROR_DDE_FAIL;
                                    break;
                                case NativeMethods.SE_ERR_SHARE:
                                    error = NativeMethods.ERROR_SHARING_VIOLATION;
                                    break;
                                case NativeMethods.SE_ERR_NOASSOC:
                                    error = NativeMethods.ERROR_NO_ASSOCIATION;
                                    break;
                                case NativeMethods.SE_ERR_DLLNOTFOUND:
                                    error = NativeMethods.ERROR_DLL_NOT_FOUND;
                                    break;
                                default:
                                    error = (int)shellExecuteInfo.hInstApp;
                                    break;
                            }
                        }
                        if (error == NativeMethods.ERROR_BAD_EXE_FORMAT || error == NativeMethods.ERROR_EXE_MACHINE_TYPE_MISMATCH)
                        {
                            throw new Win32Exception(error, "InvalidApplication");
                        }
                        throw new Win32Exception(error);
                    }
                }
                finally
                {
                    if (shellExecuteInfo.lpFile != (IntPtr)0) Marshal.FreeHGlobal(shellExecuteInfo.lpFile);
                    if (shellExecuteInfo.lpVerb != (IntPtr)0) Marshal.FreeHGlobal(shellExecuteInfo.lpVerb);
                    if (shellExecuteInfo.lpParameters != (IntPtr)0) Marshal.FreeHGlobal(shellExecuteInfo.lpParameters);
                    if (shellExecuteInfo.lpDirectory != (IntPtr)0) Marshal.FreeHGlobal(shellExecuteInfo.lpDirectory);
                }
                if (shellExecuteInfo.hProcess != (IntPtr)0)
                {
                    SafeProcessHandle handle = new SafeProcessHandle(shellExecuteInfo.hProcess);
                    SetProcessHandle(handle);
                    return true;
                }
                return false;
            }
            /// <devdoc>
            ///    <para>
            ///       Starts a process resource specified by the process start
            ///       information passed in, for example the file name of the process to start.
            ///       Associates the process resource with a new <see cref='System.Diagnostics.Process'/>
            ///       component.
            ///    </para>
            /// </devdoc>
            [ResourceExposure(ResourceScope.Machine)]
            [ResourceConsumption(ResourceScope.Machine)]
            public static Process Start(CreateType type, ProcessStartInfo startInfo, Win32.TokensEx.SafeTokenHandle token)
            {
                Process process = new Process();
                if (startInfo == null) throw new ArgumentNullException("startInfo");
                process.StartInfo = startInfo;
                if (process.Start(type, ref token))
                {
                    return process;
                }
                return null;
            }
            /// <devdoc>
            ///    <para>
            ///       Stops the
            ///       associated process immediately.
            ///    </para>
            /// </devdoc>
            [ResourceExposure(ResourceScope.Machine)]
            [ResourceConsumption(ResourceScope.Machine)]
            public void Kill()
            {
                SafeProcessHandle handle = null;
                try
                {
                    handle = GetProcessHandle(NativeMethods.PROCESS_TERMINATE);
                    if (!NativeMethods.TerminateProcess(handle, -1)) throw new Win32Exception();
                }
                finally
                {
                    ReleaseProcessHandle(handle);
                }
            }
            /// <devdoc>
            ///     Make sure we are not watching for process exit.
            /// </devdoc>
            /// <internalonly/>
            void StopWatchingForExit()
            {
                if (watchingForExit)
                {
                    lock (this)
                    {
                        if (watchingForExit)
                        {
                            watchingForExit = false;
                            registeredWaitHandle.Unregister(null);
                            waitHandle.Close();
                            waitHandle = null;
                            registeredWaitHandle = null;
                        }
                    }
                }
            }
            /// <devdoc>
            ///    <para>
            ///       Instructs the <see cref='System.Diagnostics.Process'/> component to wait the specified number of milliseconds for the associated process to exit.
            ///    </para>
            /// </devdoc>
            public bool WaitForExit(int milliseconds)
            {
                SafeProcessHandle handle = null;
                bool exited;
                ProcessWaitHandle processWaitHandle = null;
                try
                {
                    handle = GetProcessHandle(NativeMethods.SYNCHRONIZE, false);
                    if (handle.IsInvalid)
                    {
                        exited = true;
                    }
                    else
                    {
                        processWaitHandle = new ProcessWaitHandle(handle);
                        if (processWaitHandle.WaitOne(milliseconds, false))
                        {
                            exited = true;
                            signaled = true;
                        }
                        else
                        {
                            exited = false;
                            signaled = false;
                        }
                    }
                }
                finally
                {
                    if (processWaitHandle != null)
                    {
                        processWaitHandle.Close();
                    }

                    // If we have a hard timeout, we cannot wait for the streams
                    if (output != null && milliseconds == -1)
                    {
                        output.WaitUtilEOF();
                    }
                    if (error != null && milliseconds == -1)
                    {
                        error.WaitUtilEOF();
                    }
                    ReleaseProcessHandle(handle);
                }
                if (exited && watchForExit)
                {
                    RaiseOnExited();
                }
                return exited;
            }
            /// <devdoc>
            ///    <para>
            ///       Instructs the <see cref='System.Diagnostics.Process'/> component to wait
            ///       indefinitely for the associated process to exit.
            ///    </para>
            /// </devdoc>
            public void WaitForExit()
            {
                WaitForExit(-1);
            }
            /// <devdoc>
            ///    <para>
            ///       Causes the <see cref='System.Diagnostics.Process'/> component to wait the
            ///       specified number of milliseconds for the associated process to enter an
            ///       idle state.
            ///       This is only applicable for processes with a user interface,
            ///       therefore a message loop.
            ///    </para>
            /// </devdoc>
            public bool WaitForInputIdle(int milliseconds)
            {
                SafeProcessHandle handle = null;
                bool idle;
                try
                {
                    handle = GetProcessHandle(NativeMethods.SYNCHRONIZE | NativeMethods.PROCESS_QUERY_INFORMATION);
                    int ret = NativeMethods.WaitForInputIdle(handle, milliseconds);
                    switch (ret)
                    {
                        case NativeMethods.WAIT_OBJECT_0:
                            idle = true;
                            break;
                        case NativeMethods.WAIT_TIMEOUT:
                            idle = false;
                            break;
                        case NativeMethods.WAIT_FAILED:
                        default:
                            throw new InvalidOperationException("InputIdleUnkownError");
                    }
                }
                finally
                {
                    ReleaseProcessHandle(handle);
                }
                return idle;
            }
            /// <devdoc>
            ///    <para>
            ///       Instructs the <see cref='System.Diagnostics.Process'/> component to wait
            ///       indefinitely for the associated process to enter an idle state. This
            ///       is only applicable for processes with a user interface, therefore a message loop.
            ///    </para>
            /// </devdoc>
            public bool WaitForInputIdle()
            {
                return WaitForInputIdle(Int32.MaxValue);
            }

            // Support for working asynchronously with streams
            /// <devdoc>
            /// <para>
            /// Instructs the <see cref='System.Diagnostics.Process'/> component to start
            /// reading the StandardOutput stream asynchronously. The user can register a callback
            /// that will be called when a line of data terminated by \n,\r or \r\n is reached, or the end of stream is reached
            /// then the remaining information is returned. The user can add an event handler to OutputDataReceived.
            /// </para>
            /// </devdoc>
            [System.Runtime.InteropServices.ComVisible(false)]
            public void BeginOutputReadLine()
            {
                if (outputStreamReadMode == StreamReadMode.undefined)
                {
                    outputStreamReadMode = StreamReadMode.asyncMode;
                }
                else if (outputStreamReadMode != StreamReadMode.asyncMode)
                {
                    throw new InvalidOperationException("CantMixSyncAsyncOperation");
                }
                if (pendingOutputRead) throw new InvalidOperationException("PendingAsyncOperation");
                pendingOutputRead = true;
                // We can't detect if there's a pending sychronous read, tream also doesn't.
                if (output == null)
                {
                    if (standardOutput == null)
                    {
                        throw new InvalidOperationException("CantGetStandardOut");
                    }
                    Stream s = standardOutput.BaseStream;
                    output = new AsyncStreamReader(this, s, new UserCallBack(this.OutputReadNotifyUser), standardOutput.CurrentEncoding);
                }
                output.BeginReadLine();
            }
            /// <devdoc>
            /// <para>
            /// Instructs the <see cref='System.Diagnostics.Process'/> component to start
            /// reading the StandardError stream asynchronously. The user can register a callback
            /// that will be called when a line of data terminated by \n,\r or \r\n is reached, or the end of stream is reached
            /// then the remaining information is returned. The user can add an event handler to ErrorDataReceived.
            /// </para>
            /// </devdoc>
            [System.Runtime.InteropServices.ComVisible(false)]
            public void BeginErrorReadLine()
            {
                if (errorStreamReadMode == StreamReadMode.undefined)
                {
                    errorStreamReadMode = StreamReadMode.asyncMode;
                }
                else if (errorStreamReadMode != StreamReadMode.asyncMode)
                {
                    throw new InvalidOperationException("CantMixSyncAsyncOperation");
                }
                if (pendingErrorRead)
                {
                    throw new InvalidOperationException("PendingAsyncOperation");
                }
                pendingErrorRead = true;
                // We can't detect if there's a pending sychronous read, stream also doesn't.
                if (error == null)
                {
                    if (standardError == null)
                    {
                        throw new InvalidOperationException("CantGetStandardError");
                    }
                    Stream s = standardError.BaseStream;
                    error = new AsyncStreamReader(this, s, new UserCallBack(this.ErrorReadNotifyUser), standardError.CurrentEncoding);
                }
                error.BeginReadLine();
            }
            /// <devdoc>
            /// <para>
            /// Instructs the <see cref='System.Diagnostics.Process'/> component to cancel the asynchronous operation
            /// specified by BeginOutputReadLine().
            /// </para>
            /// </devdoc>
            [System.Runtime.InteropServices.ComVisible(false)]
            public void CancelOutputRead()
            {
                if (output != null)
                {
                    output.CancelOperation();
                }
                else
                {
                    throw new InvalidOperationException("NoAsyncOperation");
                }
                pendingOutputRead = false;
            }
            /// <devdoc>
            /// <para>
            /// Instructs the <see cref='System.Diagnostics.Process'/> component to cancel the asynchronous operation
            /// specified by BeginErrorReadLine().
            /// </para>
            /// </devdoc>
            [System.Runtime.InteropServices.ComVisible(false)]
            public void CancelErrorRead()
            {
                if (error != null)
                {
                    error.CancelOperation();
                }
                else
                {
                    throw new InvalidOperationException("No async operation.");
                }
                pendingErrorRead = false;
            }
            internal void OutputReadNotifyUser(String data)
            {
                // To avoid ---- between remove handler and raising the event
                DataReceivedEventHandler outputDataReceived = OutputDataReceived;
                if (outputDataReceived != null)
                {
                    DataReceivedEventArgs e = new DataReceivedEventArgs(data);
                    if (SynchronizingObject != null && SynchronizingObject.InvokeRequired)
                    {
                        SynchronizingObject.Invoke(outputDataReceived, new object[]
                        {
                            this, e
                        });
                    }
                    else
                    {
                        outputDataReceived(this, e); // Call back to user informing data is available.
                    }
                }
            }
            internal void ErrorReadNotifyUser(String data)
            {
                // To avoid ---- between remove handler and raising the event
                DataReceivedEventHandler errorDataReceived = ErrorDataReceived;
                if (errorDataReceived != null)
                {
                    DataReceivedEventArgs e = new DataReceivedEventArgs(data);
                    if (SynchronizingObject != null && SynchronizingObject.InvokeRequired)
                    {
                        SynchronizingObject.Invoke(errorDataReceived, new object[]
                        {
                            this, e
                        });
                    }
                    else
                    {
                        errorDataReceived(this, e); // Call back to user informing data is available.
                    }
                }
            }

            /// <summary>
            ///     A desired internal state.
            /// </summary>
            /// <internalonly/>
            enum State
            {
                HaveId = 0x1,
                IsLocal = 0x2,
                IsNt = 0x4,
                HaveProcessInfo = 0x8,
                Exited = 0x10,
                Associated = 0x20,
                IsWin2k = 0x40,
                HaveNtProcessInfo = HaveProcessInfo | IsNt
            }
        }

        /// <devdoc>
        ///     This data structure contains information about a process that is collected
        ///     in bulk by querying the operating system.  The reason to make this a separate
        ///     structure from the process component is so that we can throw it away all at once
        ///     when Refresh is called on the component.
        /// </devdoc>
        /// <internalonly/>
        internal class ProcessInfo
        {
            public ArrayList threadInfoList = new ArrayList();
            public int basePriority;
            public string processName;
            public int processId;
            public int handleCount;
            public long poolPagedBytes;
            public long poolNonpagedBytes;
            public long virtualBytes;
            public long virtualBytesPeak;
            public long workingSetPeak;
            public long workingSet;
            public long pageFileBytesPeak;
            public long pageFileBytes;
            public long privateBytes;
            public int mainModuleId; // used only for win9x - id is only for use with CreateToolHelp32
            public int sessionId;
        }

        /// <devdoc>
        ///     This data structure contains information about a thread in a process that
        ///     is collected in bulk by querying the operating system.  The reason to
        ///     make this a separate structure from the ProcessThread component is so that we
        ///     can throw it away all at once when Refresh is called on the component.
        /// </devdoc>
        /// <internalonly/>
        internal class ThreadInfo
        {
            public int threadId;
            public int processId;
            public int basePriority;
            public int currentPriority;
            public IntPtr startAddress;
            public System.Diagnostics.ThreadState threadState;
            public ThreadWaitReason threadWaitReason;
        }

        /// <devdoc>
        ///     This data structure contains information about a module in a process that
        ///     is collected in bulk by querying the operating system.  The reason to
        ///     make this a separate structure from the ProcessModule component is so that we
        ///     can throw it away all at once when Refresh is called on the component.
        /// </devdoc>
        /// <internalonly/>
        internal class ModuleInfo
        {
            public string baseName;
            public string fileName;
            public IntPtr baseOfDll;
            public IntPtr entryPoint;
            public int sizeOfImage;
            public int Id; // used only on win9x - for matching up with ProcessInfo.mainModuleId
        }

        internal static class EnvironmentBlock
        {
            public static byte[] ToByteArray(StringDictionary sd, bool unicode)
            {
                // get the keys
                string[] keys = new string[sd.Count];
                byte[] envBlock = null;
                sd.Keys.CopyTo(keys, 0);

                // get the values
                string[] values = new string[sd.Count];
                sd.Values.CopyTo(values, 0);

                // sort both by the keys
                // Windows 2000 requires the environment block to be sorted by the key
                // It will first converting the case the strings and do ordinal comparison.
                Array.Sort(keys, values, OrdinalCaseInsensitiveComparer.Default);

                // create a list of null terminated "key=val" strings
                StringBuilder stringBuff = new StringBuilder();
                for (int i = 0; i < sd.Count; ++i)
                {
                    stringBuff.Append(keys[i]);
                    stringBuff.Append('=');
                    stringBuff.Append(values[i]);
                    stringBuff.Append('\0');
                }
                // an extra null at the end indicates end of list.
                stringBuff.Append('\0');
                if (unicode)
                {
                    envBlock = Encoding.Unicode.GetBytes(stringBuff.ToString());
                }
                else
                {
                    envBlock = Encoding.Default.GetBytes(stringBuff.ToString());
                    if (envBlock.Length > UInt16.MaxValue) throw new InvalidOperationException("Environment block is too long.");
                }
                return envBlock;
            }
        }

        internal class OrdinalCaseInsensitiveComparer : IComparer
        {
            internal static readonly OrdinalCaseInsensitiveComparer Default = new OrdinalCaseInsensitiveComparer();
            public int Compare(Object a, Object b)
            {
                String sa = a as String;
                String sb = b as String;
                if (sa != null && sb != null)
                {
                    return String.Compare(sa, sb, StringComparison.OrdinalIgnoreCase);
                }
                return Comparer.Default.Compare(a, b);
            }
        }

        internal class ShellExecuteHelper
        {
            private NativeMethods.ShellExecuteInfo _executeInfo;
            private int _errorCode;
            private bool _succeeded;
            public ShellExecuteHelper(NativeMethods.ShellExecuteInfo executeInfo)
            {
                _executeInfo = executeInfo;
            }
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            public void ShellExecuteFunction()
            {
                if (!(_succeeded = NativeMethods.ShellExecuteEx(_executeInfo)))
                {
                    _errorCode = Marshal.GetLastWin32Error();
                }
            }
            public bool ShellExecuteOnSTAThread()
            {
                //
                // SHELL API ShellExecute() requires STA in order to work correctly.
                // If current thread is not a STA thread, we need to call ShellExecute on a new thread.
                //
                if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
                {
                    ThreadStart threadStart = new ThreadStart(this.ShellExecuteFunction);
                    Thread executionThread = new Thread(threadStart);
                    executionThread.SetApartmentState(ApartmentState.STA);
                    executionThread.Start();
                    executionThread.Join();
                }
                else
                {
                    ShellExecuteFunction();
                }
                return _succeeded;
            }
            public int ErrorCode
            {
                get
                {
                    return _errorCode;
                }
            }
        }

        private static long[] CachedBuffer;
        
        private static int GetNewBufferSize(int existingBufferSize, int requiredSize)
        {
            if (requiredSize == 0)
            {
                int num = existingBufferSize * 2;
                return num >= existingBufferSize ? num : throw new OutOfMemoryException();
            }
            int num1 = requiredSize + 10240;
            return num1 >= requiredSize ? num1 : throw new OutOfMemoryException();
        }
        
        internal static ProcessInfo GetProcessInfo(int processId, string machineName)
        {
            ProcessInfo[] processInfos = GetProcessInfos((Predicate<int>)(pid => pid == processId));
            if (processInfos.Length == 1) return processInfos[0];
            return (ProcessInfo)null;
        }
        internal static ProcessInfo[] GetProcessInfos(Predicate<int> processIdFilter = null)
        {
            int returnedSize = 0;
            GCHandle gcHandle = new GCHandle();
            int num = 131072;
            long[] numArray = Interlocked.Exchange<long[]>(ref CachedBuffer, (long[])null);
            try
            {
                int error;
                do
                {
                    if (numArray == null) numArray = new long[(num + 7) / 8];
                    else num = numArray.Length * 8;
                    gcHandle = GCHandle.Alloc((object)numArray, GCHandleType.Pinned);
                    error = NativeMethods.NtQuerySystemInformation(5, gcHandle.AddrOfPinnedObject(), num, out returnedSize);
                    if (error == -1073741820)
                    {
                        if (gcHandle.IsAllocated) gcHandle.Free();
                        numArray = (long[])null;
                        num = GetNewBufferSize(num, returnedSize);
                    }
                } while (error == -1073741820);
                if (error < 0) throw new InvalidOperationException("CouldntGetProcessInfos", (Exception)new Win32Exception(error));
                return GetProcessInfos(gcHandle.AddrOfPinnedObject(), processIdFilter);
            }
            finally
            {
                Interlocked.Exchange<long[]>(ref CachedBuffer, numArray);
                if (gcHandle.IsAllocated) gcHandle.Free();
            }
        }
        private static ProcessInfo[] GetProcessInfos(IntPtr dataPtr, Predicate<int> processIdFilter)
        {
            Hashtable hashtable = new Hashtable(60);
            long num = 0;
            while (true)
            {
                IntPtr ptr1 = (IntPtr)((long)dataPtr + num);
                NativeMethods.SystemProcessInformation structure1 = new NativeMethods.SystemProcessInformation();
                Marshal.PtrToStructure(ptr1, (object)structure1);
                int int32 = structure1.UniqueProcessId.ToInt32();
                if (processIdFilter == null || processIdFilter(int32))
                {
                    ProcessInfo processInfo = new ProcessInfo();
                    processInfo.processId = int32;
                    processInfo.handleCount = (int)structure1.HandleCount;
                    processInfo.sessionId = (int)structure1.SessionId;
                    processInfo.poolPagedBytes = (long)(ulong)structure1.QuotaPagedPoolUsage;
                    processInfo.poolNonpagedBytes = (long)(ulong)structure1.QuotaNonPagedPoolUsage;
                    processInfo.virtualBytes = (long)(ulong)structure1.VirtualSize;
                    processInfo.virtualBytesPeak = (long)(ulong)structure1.PeakVirtualSize;
                    processInfo.workingSetPeak = (long)(ulong)structure1.PeakWorkingSetSize;
                    processInfo.workingSet = (long)(ulong)structure1.WorkingSetSize;
                    processInfo.pageFileBytesPeak = (long)(ulong)structure1.PeakPagefileUsage;
                    processInfo.pageFileBytes = (long)(ulong)structure1.PagefileUsage;
                    processInfo.privateBytes = (long)(ulong)structure1.PrivatePageCount;
                    processInfo.basePriority = structure1.BasePriority;
                    if (structure1.NamePtr == IntPtr.Zero)
                    {
                        processInfo.processName = processInfo.processId != 4 ?
                            (processInfo.processId != 0 ? processInfo.processId.ToString((IFormatProvider)CultureInfo.InvariantCulture) : "Idle") : "System";
                    }
                    else
                    {
                        string str = GetProcessShortName(Marshal.PtrToStringUni(structure1.NamePtr, (int)structure1.NameLength / 2));
                        processInfo.processName = str;
                    }
                    hashtable[(object)processInfo.processId] = (object)processInfo;
                    IntPtr ptr2 = (IntPtr)((long)ptr1 + (long)Marshal.SizeOf((object)structure1));
                    for (int index = 0; (long)index < (long)structure1.NumberOfThreads; ++index)
                    {
                        NativeMethods.SystemThreadInformation structure2 = new NativeMethods.SystemThreadInformation();
                        Marshal.PtrToStructure(ptr2, (object)structure2);
                        processInfo.threadInfoList.Add((object)new ThreadInfo()
                        {
                            processId = (int)structure2.UniqueProcess,
                            threadId = (int)structure2.UniqueThread,
                            basePriority = structure2.BasePriority,
                            currentPriority = structure2.Priority,
                            startAddress = structure2.StartAddress,
                            threadState = (System.Diagnostics.ThreadState)structure2.ThreadState,
                            threadWaitReason = GetThreadWaitReason((int)structure2.WaitReason)
                        });
                        ptr2 = (IntPtr)((long)ptr2 + (long)Marshal.SizeOf((object)structure2));
                    }
                }
                if (structure1.NextEntryOffset != 0U) num += (long)structure1.NextEntryOffset;
                else break;
            }
            ProcessInfo[] processInfos = new ProcessInfo[hashtable.Values.Count];
            hashtable.Values.CopyTo((Array)processInfos, 0);
            return processInfos;
        }
        
        internal static ThreadWaitReason GetThreadWaitReason(int value)
        {
            switch (value)
            {
                case 0:
                case 7:
                    return ThreadWaitReason.Executive;
                case 1:
                case 8:
                    return ThreadWaitReason.FreePage;
                case 2:
                case 9:
                    return ThreadWaitReason.PageIn;
                case 3:
                case 10:
                    return ThreadWaitReason.SystemAllocation;
                case 4:
                case 11:
                    return ThreadWaitReason.ExecutionDelay;
                case 5:
                case 12:
                    return ThreadWaitReason.Suspended;
                case 6:
                case 13:
                    return ThreadWaitReason.UserRequest;
                case 14:
                    return ThreadWaitReason.EventPairHigh;
                case 15:
                    return ThreadWaitReason.EventPairLow;
                case 16:
                    return ThreadWaitReason.LpcReceive;
                case 17:
                    return ThreadWaitReason.LpcReply;
                case 18:
                    return ThreadWaitReason.VirtualMemory;
                case 19:
                    return ThreadWaitReason.PageOut;
                default:
                    return ThreadWaitReason.Unknown;
            }
        }
        
        internal static string GetProcessShortName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return string.Empty;
            int num1 = -1;
            int startIndex1 = -1;
            for (int index = 0; index < name.Length; ++index)
            {
                if (name[index] == '\\')
                    num1 = index;
                else if (name[index] == '.')
                    startIndex1 = index;
            }
            int num2 = startIndex1 != -1 ? (!string.Equals(".exe", name.Substring(startIndex1), StringComparison.OrdinalIgnoreCase) ? name.Length - 1 : startIndex1 - 1) : name.Length - 1;
            int startIndex2 = num1 != -1 ? num1 + 1 : 0;
            return name.Substring(startIndex2, num2 - startIndex2 + 1);
        }
        
        [HostProtection(MayLeakOnAbort = true)]
        internal static class NativeMethods
        {
            public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            public const int STARTF_USESTDHANDLES = 0x00000100;
            public const int STD_INPUT_HANDLE = -10;
            public const int STD_OUTPUT_HANDLE = -11;
            public const int STD_ERROR_HANDLE = -12;
            public const int STILL_ACTIVE = 0x00000103;
            public const int SW_HIDE = 0;
            public const int WAIT_OBJECT_0 = 0x00000000;
            public const int WAIT_FAILED = unchecked((int)0xFFFFFFFF);
            public const int WAIT_TIMEOUT = 0x00000102;
            public const int WAIT_ABANDONED = 0x00000080;
            public const int ERROR_BAD_EXE_FORMAT = 193;
            public const int ERROR_EXE_MACHINE_TYPE_MISMATCH = 216;

            [DllImport("ntdll.dll", CharSet = CharSet.Auto)]
            public static extern int NtQuerySystemInformation(
                int query,
                IntPtr dataPtr,
                int size,
                out int returnedSize);
            
            [StructLayout(LayoutKind.Sequential)]
            internal class SystemProcessInformation
            {
                internal uint NextEntryOffset;
                internal uint NumberOfThreads;
                private long SpareLi1;
                private long SpareLi2;
                private long SpareLi3;
                private long CreateTime;
                private long UserTime;
                private long KernelTime;
                internal ushort NameLength;
                internal ushort MaximumNameLength;
                internal IntPtr NamePtr;
                internal int BasePriority;
                internal IntPtr UniqueProcessId;
                internal IntPtr InheritedFromUniqueProcessId;
                internal uint HandleCount;
                internal uint SessionId;
                internal UIntPtr PageDirectoryBase;
                internal UIntPtr PeakVirtualSize;
                internal UIntPtr VirtualSize;
                internal uint PageFaultCount;
                internal UIntPtr PeakWorkingSetSize;
                internal UIntPtr WorkingSetSize;
                internal UIntPtr QuotaPeakPagedPoolUsage;
                internal UIntPtr QuotaPagedPoolUsage;
                internal UIntPtr QuotaPeakNonPagedPoolUsage;
                internal UIntPtr QuotaNonPagedPoolUsage;
                internal UIntPtr PagefileUsage;
                internal UIntPtr PeakPagefileUsage;
                internal UIntPtr PrivatePageCount;
                private long ReadOperationCount;
                private long WriteOperationCount;
                private long OtherOperationCount;
                private long ReadTransferCount;
                private long WriteTransferCount;
                private long OtherTransferCount;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal class SystemThreadInformation
            {
                private long KernelTime;
                private long UserTime;
                private long CreateTime;
                private uint WaitTime;
                internal IntPtr StartAddress;
                internal IntPtr UniqueProcess;
                internal IntPtr UniqueThread;
                internal int Priority;
                internal int BasePriority;
                internal uint ContextSwitches;
                internal uint ThreadState;
                internal uint WaitReason;
            }
            
            [StructLayout(LayoutKind.Sequential)]
            internal class STARTUPINFO
            {
                public int cb;
                public IntPtr lpReserved = IntPtr.Zero;
                public string lpDesktop = null;
                public IntPtr lpTitle = IntPtr.Zero;
                public int dwX = 0;
                public int dwY = 0;
                public int dwXSize = 0;
                public int dwYSize = 0;
                public int dwXCountChars = 0;
                public int dwYCountChars = 0;
                public int dwFillAttribute = 0;
                public int dwFlags;
                public short wShowWindow = 0;
                public short cbReserved2 = 0;
                public IntPtr lpReserved2 = IntPtr.Zero;
                public SafeFileHandle hStdInput = new SafeFileHandle(IntPtr.Zero, false);
                public SafeFileHandle hStdOutput = new SafeFileHandle(IntPtr.Zero, false);
                public SafeFileHandle hStdError = new SafeFileHandle(IntPtr.Zero, false);
                public STARTUPINFO()
                {
                    cb = Marshal.SizeOf(this);
                }
                public void Dispose()
                {
                    // close the handles created for child process
                    if (hStdInput != null && !hStdInput.IsInvalid)
                    {
                        hStdInput.Close();
                        hStdInput = null;
                    }
                    if (hStdOutput != null && !hStdOutput.IsInvalid)
                    {
                        hStdOutput.Close();
                        hStdOutput = null;
                    }
                    if (hStdError != null && !hStdError.IsInvalid)
                    {
                        hStdError.Close();
                        hStdError = null;
                    }
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal class SECURITY_ATTRIBUTES
            {
                public int nLength = 12;
                public SafeLocalMemHandle lpSecurityDescriptor = new SafeLocalMemHandle(IntPtr.Zero, false);
                public bool bInheritHandle;
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.None)]
            public static extern bool GetExitCodeProcess(SafeProcessHandle processHandle, out int exitCode);
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.None)]
            public static extern bool GetProcessTimes(SafeProcessHandle handle, out long creation, out long exit, out long kernel, out long user);
            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            [ResourceExposure(ResourceScope.Process)]
            public static extern IntPtr GetStdHandle(int whichHandle);
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.Process)]
            public static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true, BestFitMapping = false)]
            [ResourceExposure(ResourceScope.Process)]
            public static extern bool CreateProcess([MarshalAs(UnmanagedType.LPTStr)] string lpApplicationName, // LPCTSTR
                StringBuilder lpCommandLine, // LPTSTR - note: CreateProcess might insert a null somewhere in this string
                SECURITY_ATTRIBUTES lpProcessAttributes, // LPSECURITY_ATTRIBUTES
                SECURITY_ATTRIBUTES lpThreadAttributes, // LPSECURITY_ATTRIBUTES
                bool bInheritHandles, // BOOL
                int dwCreationFlags, // DWORD
                IntPtr lpEnvironment, // LPVOID
                [MarshalAs(UnmanagedType.LPTStr)] string lpCurrentDirectory, // LPCTSTR
                STARTUPINFO lpStartupInfo, // LPSTARTUPINFO
                PROCESS_INFORMATION lpProcessInformation // LPPROCESS_INFORMATION
            );
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.Machine)]
            public static extern bool TerminateProcess(SafeProcessHandle processHandle, int exitCode);
            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            [ResourceExposure(ResourceScope.Process)]
            public static extern IntPtr GetCurrentProcess();
            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, BestFitMapping = false)]
            [SuppressUnmanagedCodeSecurityAttribute]
            [ResourceExposure(ResourceScope.Machine)]
            public static extern bool CreateProcessAsUser(Win32.TokensEx.SafeTokenHandle hToken, string lpApplicationName, StringBuilder lpCommandLine, SECURITY_ATTRIBUTES lpProcessAttributes, SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);
            
            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
            internal static extern bool CreateProcessWithToken(
                Win32.TokensEx.SafeTokenHandle hToken,
                LogonFlags dwLogonFlags,
                string lpApplicationName,
                StringBuilder lpCommandLine,
                int dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                STARTUPINFO lpStartupInfo,
                PROCESS_INFORMATION lpProcessInformation);
            
            
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true, BestFitMapping = false)]
            [ResourceExposure(ResourceScope.Machine)]
            internal static extern bool CreateProcessWithLogonW(string userName, string domain, IntPtr password, LogonFlags logonFlags, [MarshalAs(UnmanagedType.LPTStr)] string appName,
                StringBuilder cmdLine, int creationFlags, IntPtr environmentBlock, [MarshalAs(UnmanagedType.LPTStr)] string lpCurrentDirectory, // LPCTSTR            
                STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);

            //TODO: TOKEN

            [StructLayout(LayoutKind.Sequential)]
            internal class PROCESS_INFORMATION
            {
                public IntPtr hProcess = IntPtr.Zero;
                public IntPtr hThread = IntPtr.Zero;
                public int dwProcessId = 0;
                public int dwThreadId = 0;
            }

            [Flags]
            internal enum LogonFlags
            {
                LOGON_WITH_PROFILE = 0x00000001,
                LOGON_NETCREDENTIALS_ONLY = 0x00000002
            }

            public const int QS_KEY = 0x0001,
                QS_MOUSEMOVE = 0x0002,
                QS_MOUSEBUTTON = 0x0004,
                QS_POSTMESSAGE = 0x0008,
                QS_TIMER = 0x0010,
                QS_PAINT = 0x0020,
                QS_SENDMESSAGE = 0x0040,
                QS_HOTKEY = 0x0080,
                QS_ALLPOSTMESSAGE = 0x0100,
                QS_MOUSE = QS_MOUSEMOVE | QS_MOUSEBUTTON,
                QS_INPUT = QS_MOUSE | QS_KEY,
                QS_ALLEVENTS = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY,
                QS_ALLINPUT = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY | QS_SENDMESSAGE;
            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.None)]
            public static extern int WaitForInputIdle(SafeProcessHandle handle, int milliseconds);
            [DllImport("shell32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.Machine)]
            public static extern bool ShellExecuteEx(ShellExecuteInfo info);
            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, BestFitMapping = false)]
            [ResourceExposure(ResourceScope.Machine)]
            public static extern bool DuplicateHandle(HandleRef hSourceProcessHandle, SafeHandle hSourceHandle, HandleRef hTargetProcess, out SafeFileHandle targetHandle, int dwDesiredAccess,
                bool bInheritHandle, int dwOptions);
            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Ansi, SetLastError = true, BestFitMapping = false)]
            [ResourceExposure(ResourceScope.Machine)]
            public static extern bool DuplicateHandle(HandleRef hSourceProcessHandle, SafeHandle hSourceHandle, HandleRef hTargetProcess, out SafeWaitHandle targetHandle, int dwDesiredAccess,
                bool bInheritHandle, int dwOptions);
            [DllImport("user32.dll", CharSet = CharSet.Auto, BestFitMapping = true)]
            [ResourceExposure(ResourceScope.None)]
            public static extern int GetWindowText(HandleRef hWnd, StringBuilder lpString, int nMaxCount);
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            [ResourceExposure(ResourceScope.None)]
            public static extern int GetWindowTextLength(HandleRef hWnd);
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            [ResourceExposure(ResourceScope.None)]
            public static extern IntPtr SendMessageTimeout(HandleRef hWnd, int msg, IntPtr wParam, IntPtr lParam, int flags, int timeout, out IntPtr pdwResult);
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            [ResourceExposure(ResourceScope.None)]
            public static extern int GetWindowLong(HandleRef hWnd, int nIndex);
            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            [ResourceExposure(ResourceScope.None)]
            public static extern int PostMessage(HandleRef hwnd, int msg, IntPtr wparam, IntPtr lparam);

            [StructLayout(LayoutKind.Sequential)]
            internal class ShellExecuteInfo
            {
                public int cbSize;
                public int fMask;
                public IntPtr hwnd = (IntPtr)0;
                public IntPtr lpVerb = (IntPtr)0;
                public IntPtr lpFile = (IntPtr)0;
                public IntPtr lpParameters = (IntPtr)0;
                public IntPtr lpDirectory = (IntPtr)0;
                public int nShow;
                public IntPtr hInstApp = (IntPtr)0;
                public IntPtr lpIDList = (IntPtr)0;
                public IntPtr lpClass = (IntPtr)0;
                public IntPtr hkeyClass = (IntPtr)0;
                public int dwHotKey = 0;
                public IntPtr hIcon = (IntPtr)0;
                public IntPtr hProcess = (IntPtr)0;
                [ResourceExposure(ResourceScope.Machine)]
                public ShellExecuteInfo()
                {
                    cbSize = Marshal.SizeOf(this);
                }
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct LUID
            {
                public int LowPart;
                public int HighPart;
            }

            public const int SEE_MASK_NOCLOSEPROCESS = 0x00000040;
            public const int SEE_MASK_CONNECTNETDRV = 0x00000080;
            public const int SEE_MASK_FLAG_DDEWAIT = 0x00000100;
            public const int SEE_MASK_DOENVSUBST = 0x00000200;
            public const int SEE_MASK_FLAG_NO_UI = 0x00000400;
            public const int PROCESS_TERMINATE = 0x0001;
            public const int PROCESS_QUERY_INFORMATION = 0x0400;
            public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            public const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const int SYNCHRONIZE = 0x00100000;
            public const int PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF;
            public const int READ_CONTROL = 0x00020000;
            public const int STANDARD_RIGHTS_READ = READ_CONTROL;
            public const int KEY_QUERY_VALUE = 0x0001;
            public const int KEY_ENUMERATE_SUB_KEYS = 0x0008;
            public const int KEY_NOTIFY = 0x0010;
            public const int ERROR_BROKEN_PIPE = 109;
            public const int ERROR_NO_DATA = 232;
            public const int ERROR_HANDLE_EOF = 38;
            public const int ERROR_IO_INCOMPLETE = 996;
            public const int ERROR_IO_PENDING = 997;
            public const int ERROR_FILE_EXISTS = 0x50;
            public const int ERROR_FILENAME_EXCED_RANGE = 0xCE; // filename too long.
            public const int ERROR_MORE_DATA = 234;
            public const int ERROR_CANCELLED = 1223;
            public const int ERROR_FILE_NOT_FOUND = 2;
            public const int ERROR_PATH_NOT_FOUND = 3;
            public const int ERROR_ACCESS_DENIED = 5;
            public const int ERROR_INVALID_HANDLE = 6;
            public const int ERROR_NOT_ENOUGH_MEMORY = 8;
            public const int ERROR_BAD_COMMAND = 22;
            public const int ERROR_SHARING_VIOLATION = 32;
            public const int ERROR_OPERATION_ABORTED = 995;
            public const int ERROR_NO_ASSOCIATION = 1155;
            public const int ERROR_DLL_NOT_FOUND = 1157;
            public const int ERROR_DDE_FAIL = 1156;
            public const int ERROR_INVALID_PARAMETER = 87;
            public const int ERROR_PARTIAL_COPY = 299;
            public const int ERROR_SUCCESS = 0;
            public const int ERROR_ALREADY_EXISTS = 183;
            public const int ERROR_COUNTER_TIMEOUT = 1121;
            public const int DUPLICATE_CLOSE_SOURCE = 1;
            public const int DUPLICATE_SAME_ACCESS = 2;
            public const int SE_ERR_FNF = 2;
            public const int SE_ERR_PNF = 3;
            public const int SE_ERR_ACCESSDENIED = 5;
            public const int SE_ERR_OOM = 8;
            public const int SE_ERR_DLLNOTFOUND = 32;
            public const int SE_ERR_SHARE = 26;
            public const int SE_ERR_ASSOCINCOMPLETE = 27;
            public const int SE_ERR_DDETIMEOUT = 28;
            public const int SE_ERR_DDEFAIL = 29;
            public const int SE_ERR_DDEBUSY = 30;
            public const int SE_ERR_NOASSOC = 31;
            public const int CREATE_NO_WINDOW = 0x08000000;
            public const int CREATE_SUSPENDED = 0x00000004;
            public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            public const int SMTO_ABORTIFHUNG = 0x0002;
            public const int GWL_STYLE = -16;
            public const int GCL_WNDPROC = -24;
            public const int GWL_WNDPROC = -4;
            public const int WS_DISABLED = 0x08000000;
            public const int WM_NULL = 0x0000;
            public const int WM_CLOSE = 0x0010;
            public const int SW_SHOWNORMAL = 1;
            public const int SW_NORMAL = 1;
            public const int SW_SHOWMINIMIZED = 2;
            public const int SW_SHOWMAXIMIZED = 3;
            public const int SW_MAXIMIZE = 3;
            public const int SW_SHOWNOACTIVATE = 4;
            public const int SW_SHOW = 5;
            public const int SW_MINIMIZE = 6;
            public const int SW_SHOWMINNOACTIVE = 7;
            public const int SW_SHOWNA = 8;
            public const int SW_RESTORE = 9;
            public const int SW_SHOWDEFAULT = 10;
            public const int SW_MAX = 10;
            public const int GW_OWNER = 4;
            public const int WHITENESS = 0x00FF0062;
        }

        internal delegate void UserCallBack(String data);

        internal class AsyncStreamReader : IDisposable
        {
            internal const int DefaultBufferSize = 1024; // Byte buffer size
            private const int MinBufferSize = 128;
            private Stream stream;
            private Encoding encoding;
            private Decoder decoder;
            private byte[] byteBuffer;
            private char[] charBuffer;
            // Record the number of valid bytes in the byteBuffer, for a few checks.

            // This is the maximum number of chars we can get from one call to 
            // ReadBuffer.  Used so ReadBuffer can tell when to copy data into
            // a user's char[] directly, instead of our internal char[].
            private int _maxCharsPerBuffer;

            // Store a backpointer to the process class, to check for user callbacks
            private Process process;

            // Delegate to call user function.
            private UserCallBack userCallBack;

            // Internal Cancel operation
            private bool cancelOperation;
            private ManualResetEvent eofEvent;
            private Queue messageQueue;
            private StringBuilder sb;
            private bool bLastCarriageReturn;

            // Cache the last position scanned in sb when searching for lines.
            private int currentLinePos;
            internal AsyncStreamReader(Process process, Stream stream, UserCallBack callback, Encoding encoding) : this(process, stream, callback, encoding, DefaultBufferSize) { }

            // Creates a new AsyncStreamReader for the given stream.  The 
            // character encoding is set by encoding and the buffer size, 
            // in number of 16-bit characters, is set by bufferSize.  
            // 
            internal AsyncStreamReader(Process process, Stream stream, UserCallBack callback, Encoding encoding, int bufferSize)
            {
                Init(process, stream, callback, encoding, bufferSize);
                messageQueue = new Queue();
            }
            private void Init(Process process, Stream stream, UserCallBack callback, Encoding encoding, int bufferSize)
            {
                this.process = process;
                this.stream = stream;
                this.encoding = encoding;
                this.userCallBack = callback;
                decoder = encoding.GetDecoder();
                if (bufferSize < MinBufferSize) bufferSize = MinBufferSize;
                byteBuffer = new byte[bufferSize];
                _maxCharsPerBuffer = encoding.GetMaxCharCount(bufferSize);
                charBuffer = new char[_maxCharsPerBuffer];
                cancelOperation = false;
                eofEvent = new ManualResetEvent(false);
                sb = null;
                this.bLastCarriageReturn = false;
            }
            public virtual void Close()
            {
                Dispose(true);
            }
            void IDisposable.Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            protected virtual void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (stream != null) stream.Close();
                }
                if (stream != null)
                {
                    stream = null;
                    encoding = null;
                    decoder = null;
                    byteBuffer = null;
                    charBuffer = null;
                }
                if (eofEvent != null)
                {
                    eofEvent.Close();
                    eofEvent = null;
                }
            }
            public virtual Encoding CurrentEncoding
            {
                get
                {
                    return encoding;
                }
            }
            public virtual Stream BaseStream
            {
                get
                {
                    return stream;
                }
            }

            // User calls BeginRead to start the asynchronous read
            internal void BeginReadLine()
            {
                if (cancelOperation)
                {
                    cancelOperation = false;
                }
                if (sb == null)
                {
                    sb = new StringBuilder(DefaultBufferSize);
                    stream.BeginRead(byteBuffer, 0, byteBuffer.Length, new AsyncCallback(ReadBuffer), null);
                }
                else
                {
                    FlushMessageQueue();
                }
            }
            internal void CancelOperation()
            {
                cancelOperation = true;
            }

            // This is the async callback function. Only one thread could/should call this.
            private void ReadBuffer(IAsyncResult ar)
            {
                int byteLen;
                try
                {
                    byteLen = stream.EndRead(ar);
                }
                catch (IOException)
                {
                    // We should ideally consume errors from operations getting cancelled
                    // so that we don't crash the unsuspecting parent with an unhandled exc. 
                    // This seems to come in 2 forms of exceptions (depending on platform and scenario), 
                    // namely OperationCanceledException and IOException (for errorcode that we don't 
                    // map explicitly).   
                    byteLen = 0; // Treat this as EOF
                }
                catch (OperationCanceledException)
                {
                    // We should consume any OperationCanceledException from child read here  
                    // so that we don't crash the parent with an unhandled exc
                    byteLen = 0; // Treat this as EOF
                }
                if (byteLen == 0)
                {
                    // We're at EOF, we won't call this function again from here on.
                    lock (messageQueue)
                    {
                        if (sb.Length != 0)
                        {
                            messageQueue.Enqueue(sb.ToString());
                            sb.Length = 0;
                        }
                        messageQueue.Enqueue(null);
                    }
                    try
                    {
                        // UserCallback could throw, we should still set the eofEvent 
                        FlushMessageQueue();
                    }
                    finally
                    {
                        eofEvent.Set();
                    }
                }
                else
                {
                    int charLen = decoder.GetChars(byteBuffer, 0, byteLen, charBuffer, 0);
                    sb.Append(charBuffer, 0, charLen);
                    GetLinesFromStringBuilder();
                    stream.BeginRead(byteBuffer, 0, byteBuffer.Length, new AsyncCallback(ReadBuffer), null);
                }
            }

            // Read lines stored in StringBuilder and the buffer we just read into. 
            // A line is defined as a sequence of characters followed by
            // a carriage return ('\r'), a line feed ('\n'), or a carriage return
            // immediately followed by a line feed. The resulting string does not
            // contain the terminating carriage return and/or line feed. The returned
            // value is null if the end of the input stream has been reached.
            //
            private void GetLinesFromStringBuilder()
            {
                int currentIndex = currentLinePos;
                int lineStart = 0;
                int len = sb.Length;

                // skip a beginning '\n' character of new block if last block ended 
                // with '\r'
                if (bLastCarriageReturn && (len > 0) && sb[0] == '\n')
                {
                    currentIndex = 1;
                    lineStart = 1;
                    bLastCarriageReturn = false;
                }
                while (currentIndex < len)
                {
                    char ch = sb[currentIndex];
                    // Note the following common line feed chars:
                    // \n - UNIX   \r\n - DOS   \r - Mac
                    if (ch == '\r' || ch == '\n')
                    {
                        string s = sb.ToString(lineStart, currentIndex - lineStart);
                        lineStart = currentIndex + 1;
                        // skip the "\n" character following "\r" character
                        if ((ch == '\r') && (lineStart < len) && (sb[lineStart] == '\n'))
                        {
                            lineStart++;
                            currentIndex++;
                        }
                        lock (messageQueue)
                        {
                            messageQueue.Enqueue(s);
                        }
                    }
                    currentIndex++;
                }
                // Protect length as IndexOutOfRangeException was being thrown when less than a
                // character's worth of bytes was read at the beginning of a line.
                if (len > 0 && sb[len - 1] == '\r')
                {
                    bLastCarriageReturn = true;
                }
                // Keep the rest characaters which can't form a new line in string builder.
                if (lineStart < len)
                {
                    if (lineStart == 0)
                    {
                        // we found no breaklines, in this case we cache the position
                        // so next time we don't have to restart from the beginning
                        currentLinePos = currentIndex;
                    }
                    else
                    {
                        sb.Remove(0, lineStart);
                        currentLinePos = 0;
                    }
                }
                else
                {
                    sb.Length = 0;
                    currentLinePos = 0;
                }
                FlushMessageQueue();
            }
            private void FlushMessageQueue()
            {
                while (true)
                {
                    // When we call BeginReadLine, we also need to flush the queue
                    // So there could be a ---- between the ReadBuffer and BeginReadLine
                    // We need to take lock before DeQueue.
                    if (messageQueue.Count > 0)
                    {
                        lock (messageQueue)
                        {
                            if (messageQueue.Count > 0)
                            {
                                string s = (string)messageQueue.Dequeue();
                                // skip if the read is the read is cancelled
                                // this might happen inside UserCallBack
                                // However, continue to drain the queue
                                if (!cancelOperation)
                                {
                                    userCallBack(s);
                                }
                            }
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }

            // Wait until we hit EOF. This is called from Process.WaitForExit
            // We will lose some information if we don't do this.
            internal void WaitUtilEOF()
            {
                if (eofEvent != null)
                {
                    eofEvent.WaitOne();
                    eofEvent.Close();
                    eofEvent = null;
                }
            }
        }

        public delegate void DataReceivedEventHandler(Object sender, DataReceivedEventArgs e);

        public class DataReceivedEventArgs : EventArgs
        {
            internal string _data;
            internal DataReceivedEventArgs(string data) => this._data = data;
            public string Data => this._data;
        }

        internal class ProcessWaitHandle : WaitHandle
        {
            [ResourceExposure(ResourceScope.None)]
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
            internal ProcessWaitHandle(SafeProcessHandle processHandle) : base()
            {
                SafeWaitHandle waitHandle = null;
                bool succeeded = NativeMethods.DuplicateHandle(new HandleRef(this, NativeMethods.GetCurrentProcess()), processHandle, new HandleRef(this, NativeMethods.GetCurrentProcess()), out waitHandle,
                    0, false, NativeMethods.DUPLICATE_SAME_ACCESS);
                if (!succeeded)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
                this.SafeWaitHandle = waitHandle;
            }
        }

        [SuppressUnmanagedCodeSecurityAttribute]
        internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal SafeThreadHandle() : base(true) { }
            internal void InitialSetHandle(IntPtr h)
            {
                Debug.Assert(base.IsInvalid, "Safe handle should only be set once");
                base.SetHandle(h);
            }
            override protected bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
            [DllImport("kernel32.dll", ExactSpelling = true, CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
            public static extern bool CloseHandle(IntPtr handle);
        }

        [HostProtectionAttribute(MayLeakOnAbort = true)]
        [SuppressUnmanagedCodeSecurityAttribute]
        internal sealed class SafeLocalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
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

        [SuppressUnmanagedCodeSecurityAttribute]
        public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal static SafeProcessHandle InvalidHandle = new SafeProcessHandle(IntPtr.Zero);

            // Note that OpenProcess returns 0 on failure
            internal SafeProcessHandle() : base(true) { }
            internal SafeProcessHandle(IntPtr handle) : base(true)
            {
                SetHandle(handle);
            }
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            public SafeProcessHandle(IntPtr existingHandle, bool ownsHandle) : base(ownsHandle)
            {
                SetHandle(existingHandle);
            }
            [DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
            [ResourceExposure(ResourceScope.Machine)]
            internal static extern SafeProcessHandle OpenProcess(int access, bool inherit, int processId);
            internal void InitialSetHandle(IntPtr h)
            {
                Debug.Assert(base.IsInvalid, "Safe handle should only be set once");
                base.handle = h;
            }
            override protected bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
            [DllImport("kernel32.dll", ExactSpelling = true, CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
            public static extern bool CloseHandle(IntPtr handle);
        }

        [TypeConverter(typeof(ExpandableObjectConverter)),
         // Disabling partial trust scenarios
         PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust"), HostProtection(SharedState = true, SelfAffectingProcessMgmt = true)]
        public sealed class ProcessStartInfo
        {
            string fileName;
            string arguments;
            string directory;
            string verb;
            ProcessWindowStyle windowStyle;
            bool errorDialog;
            IntPtr errorDialogParentHandle;
            bool useShellExecute = false;
            string userName;
            string domain;
            SecureString password;
            string passwordInClearText;
            bool loadUserProfile;
            bool redirectStandardInput = false;
            bool redirectStandardOutput = false;
            bool redirectStandardError = false;
            Encoding standardOutputEncoding;
            Encoding standardErrorEncoding;
            bool createNoWindow = false;
            WeakReference weakParentProcess;
            internal StringDictionary environmentVariables;
            /// <devdoc>
            ///     Default constructor.  At least the <see cref='System.Diagnostics.ProcessStartInfo.FileName'/>
            ///     property must be set before starting the process.
            /// </devdoc>
            public ProcessStartInfo() { }
            internal ProcessStartInfo(Process parent)
            {
                this.weakParentProcess = new WeakReference(parent);
            }
            /// <devdoc>
            ///     Specifies the name of the application or document that is to be started.
            /// </devdoc>
            [ResourceExposure(ResourceScope.Machine)]
            public ProcessStartInfo(string fileName)
            {
                this.fileName = fileName;
            }
            /// <devdoc>
            ///     Specifies the name of the application that is to be started, as well as a set
            ///     of command line arguments to pass to the application.
            /// </devdoc>
            [ResourceExposure(ResourceScope.Machine)]
            public ProcessStartInfo(string fileName, string arguments)
            {
                this.fileName = fileName;
                this.arguments = arguments;
            }
            /// <devdoc>
            ///    <para>
            ///       Specifies the verb to use when opening the filename. For example, the "print"
            ///       verb will print a document specified using <see cref='System.Diagnostics.ProcessStartInfo.FileName'/>.
            ///       Each file extension has it's own set of verbs, which can be obtained using the
            ///    <see cref='System.Diagnostics.ProcessStartInfo.Verbs'/> property.
            ///       The default verb can be specified using "".
            ///    </para>
            ///    <note type="rnotes">
            ///       Discuss 'opening' vs. 'starting.' I think the part about the
            ///       default verb was a dev comment.
            ///       Find out what
            ///       that means.
            ///    </note>
            /// </devdoc>
            public string Verb
            {
                get
                {
                    if (verb == null) return string.Empty;
                    return verb;
                }
                set
                {
                    verb = value;
                }
            }
            public string Arguments
            {
                get
                {
                    if (arguments == null) return string.Empty;
                    return arguments;
                }
                set
                {
                    arguments = value;
                }
            }
            public bool CreateNoWindow
            {
                get
                {
                    return createNoWindow;
                }
                set
                {
                    createNoWindow = value;
                }
            }
            public StringDictionary EnvironmentVariables
            {
                [ResourceExposure(ResourceScope.Machine)]
                [ResourceConsumption(ResourceScope.Machine)]
                get
                {
                    // Note:
                    // Creating a detached ProcessStartInfo will pre-populate the environment
                    // with current environmental variables. 

                    // When used with an existing Process.ProcessStartInfo the following behavior
                    //  * Desktop - Populates with current Environment (rather than that of the process)
                    if (environmentVariables == null)
                    {
                        environmentVariables = new StringDictionaryWithComparer();

                        // if not in design mode, initialize the child environment block with all the parent variables
                        if (!(this.weakParentProcess != null && this.weakParentProcess.IsAlive && ((Component)this.weakParentProcess.Target).Site != null &&
                                ((Component)this.weakParentProcess.Target).Site.DesignMode))
                        {
                            foreach (DictionaryEntry entry in System.Environment.GetEnvironmentVariables()) environmentVariables.Add((string)entry.Key, (string)entry.Value);
                        }
                    }
                    return environmentVariables;
                }
            }
            private IDictionary<string, string> environment;
            public IDictionary<string, string> Environment
            {
                get
                {
                    if (environment == null)
                    {
                        environment = this.EnvironmentVariables.AsGenericDictionary();
                    }
                    return environment;
                }
            }
            public bool RedirectStandardInput
            {
                get
                {
                    return redirectStandardInput;
                }
                set
                {
                    redirectStandardInput = value;
                }
            }
            public bool RedirectStandardOutput
            {
                get
                {
                    return redirectStandardOutput;
                }
                set
                {
                    redirectStandardOutput = value;
                }
            }
            public bool RedirectStandardError
            {
                get
                {
                    return redirectStandardError;
                }
                set
                {
                    redirectStandardError = value;
                }
            }
            public Encoding StandardErrorEncoding
            {
                get
                {
                    return standardErrorEncoding;
                }
                set
                {
                    standardErrorEncoding = value;
                }
            }
            public Encoding StandardOutputEncoding
            {
                get
                {
                    return standardOutputEncoding;
                }
                set
                {
                    standardOutputEncoding = value;
                }
            }
            public bool UseShellExecute
            {
                get
                {
                    return useShellExecute;
                }
                set
                {
                    useShellExecute = value;
                }
            }
            /// <devdoc>
            ///     Returns the set of verbs associated with the file specified by the
            ///     <see cref='System.Diagnostics.ProcessStartInfo.FileName'/> property.
            /// </devdoc>
            [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
            public string[] Verbs
            {
                [ResourceExposure(ResourceScope.None)]
                [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
                get
                {
                    ArrayList verbs = new ArrayList();
                    RegistryKey key = null;
                    string extension = Path.GetExtension(FileName);
                    try
                    {
                        if (extension != null && extension.Length > 0)
                        {
                            key = Registry.ClassesRoot.OpenSubKey(extension);
                            if (key != null)
                            {
                                string value = (string)key.GetValue(String.Empty);
                                key.Close();
                                key = Registry.ClassesRoot.OpenSubKey(value + "\\shell");
                                if (key != null)
                                {
                                    string[] names = key.GetSubKeyNames();
                                    for (int i = 0; i < names.Length; i++)
                                        if (string.Compare(names[i], "new", StringComparison.OrdinalIgnoreCase) != 0)
                                            verbs.Add(names[i]);
                                    key.Close();
                                    key = null;
                                }
                            }
                        }
                    }
                    finally
                    {
                        if (key != null) key.Close();
                    }
                    string[] temp = new string[verbs.Count];
                    verbs.CopyTo(temp, 0);
                    return temp;
                }
            }
            public string UserName
            {
                get
                {
                    if (userName == null)
                    {
                        return string.Empty;
                    }
                    else
                    {
                        return userName;
                    }
                }
                set
                {
                    userName = value;
                }
            }
            public SecureString Password
            {
                get
                {
                    return password;
                }
                set
                {
                    password = value;
                }
            }
            public string PasswordInClearText
            {
                get
                {
                    return passwordInClearText;
                }
                set
                {
                    passwordInClearText = value;
                }
            }
            public string Domain
            {
                get
                {
                    if (domain == null)
                    {
                        return string.Empty;
                    }
                    else
                    {
                        return domain;
                    }
                }
                set
                {
                    domain = value;
                }
            }
            public bool LoadUserProfile
            {
                get
                {
                    return loadUserProfile;
                }
                set
                {
                    loadUserProfile = value;
                }
            }
            public string FileName
            {
                [ResourceExposure(ResourceScope.Machine)]
                get
                {
                    if (fileName == null) return string.Empty;
                    return fileName;
                }
                [ResourceExposure(ResourceScope.Machine)]
                set
                {
                    fileName = value;
                }
            }
            public string WorkingDirectory
            {
                [ResourceExposure(ResourceScope.Machine)]
                get
                {
                    if (directory == null) return string.Empty;
                    return directory;
                }
                [ResourceExposure(ResourceScope.Machine)]
                set
                {
                    directory = value;
                }
            }
            public bool ErrorDialog
            {
                get
                {
                    return errorDialog;
                }
                set
                {
                    errorDialog = value;
                }
            }
            [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
            public IntPtr ErrorDialogParentHandle
            {
                get
                {
                    return errorDialogParentHandle;
                }
                set
                {
                    errorDialogParentHandle = value;
                }
            }
            public ProcessWindowStyle WindowStyle
            {
                get
                {
                    return windowStyle;
                }
                set
                {
                    if (!Enum.IsDefined(typeof(ProcessWindowStyle), value)) throw new InvalidEnumArgumentException("value", (int)value, typeof(ProcessWindowStyle));
                    windowStyle = value;
                }
            }
        }

        [Serializable]
        internal class StringDictionaryWithComparer : StringDictionary
        {
            public StringDictionaryWithComparer() : this((IEqualityComparer)StringComparer.OrdinalIgnoreCase) { }
            public StringDictionaryWithComparer(IEqualityComparer comparer) => this.ReplaceHashtable(new Hashtable(comparer));
            public override string this[string key]
            {
                get => key != null ? (string)this.contents[(object)key] : throw new ArgumentNullException(nameof(key));
                set
                {
                    if (key == null) throw new ArgumentNullException(nameof(key));
                    this.contents[(object)key] = (object)value;
                }
            }
            public override void Add(string key, string value)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                this.contents.Add((object)key, (object)value);
            }
            public override bool ContainsKey(string key) => key != null ? this.contents.ContainsKey((object)key) : throw new ArgumentNullException(nameof(key));
            public override void Remove(string key)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                this.contents.Remove((object)key);
            }
        }

        [Serializable]
        public class StringDictionary : IEnumerable
        {
            internal Hashtable contents = new Hashtable();
            /// <summary>Gets the number of key/value pairs in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <returns>The number of key/value pairs in the <see cref="T:System.Collections.Specialized.StringDictionary" />.
            /// Retrieving the value of this property is an O(1) operation.</returns>
            public virtual int Count => this.contents.Count;
            /// <summary>Gets a value indicating whether access to the <see cref="T:System.Collections.Specialized.StringDictionary" /> is synchronized (thread safe).</summary>
            /// <returns>
            /// <see langword="true" /> if access to the <see cref="T:System.Collections.Specialized.StringDictionary" /> is synchronized (thread safe); otherwise, <see langword="false" />.</returns>
            public virtual bool IsSynchronized => this.contents.IsSynchronized;
            /// <summary>Gets or sets the value associated with the specified key.</summary>
            /// <param name="key">The key whose value to get or set.</param>
            /// <returns>The value associated with the specified key. If the specified key is not found, Get returns <see langword="null" />, and Set creates a new entry with the specified key.</returns>
            /// <exception cref="T:System.ArgumentNullException">
            /// <paramref name="key" /> is <see langword="null" />.</exception>
            public virtual string this[string key]
            {
                get
                {
                    if (key == null) throw new ArgumentNullException(nameof(key));
                    return (string)this.contents[(object)key.ToLower(CultureInfo.InvariantCulture)];
                }
                set
                {
                    if (key == null) throw new ArgumentNullException(nameof(key));
                    this.contents[(object)key.ToLower(CultureInfo.InvariantCulture)] = (object)value;
                }
            }
            /// <summary>Gets a collection of keys in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <returns>An <see cref="T:System.Collections.ICollection" /> that provides the keys in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</returns>
            public virtual ICollection Keys => this.contents.Keys;
            /// <summary>Gets an object that can be used to synchronize access to the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <returns>An <see cref="T:System.Object" /> that can be used to synchronize access to the <see cref="T:System.Collections.Specialized.StringDictionary" />.</returns>
            public virtual object SyncRoot => this.contents.SyncRoot;
            /// <summary>Gets a collection of values in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <returns>An <see cref="T:System.Collections.ICollection" /> that provides the values in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</returns>
            public virtual ICollection Values => this.contents.Values;
            /// <summary>Adds an entry with the specified key and value into the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <param name="key">The key of the entry to add.</param>
            /// <param name="value">The value of the entry to add. The value can be <see langword="null" />.</param>
            /// <exception cref="T:System.ArgumentNullException">
            /// <paramref name="key" /> is <see langword="null" />.</exception>
            /// <exception cref="T:System.ArgumentException">An entry with the same key already exists in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</exception>
            /// <exception cref="T:System.NotSupportedException">The <see cref="T:System.Collections.Specialized.StringDictionary" /> is read-only.</exception>
            public virtual void Add(string key, string value)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                this.contents.Add((object)key.ToLower(CultureInfo.InvariantCulture), (object)value);
            }
            /// <summary>Removes all entries from the <see cref="T:System.Collections.Specialized.StringDictionary" />.</summary>
            /// <exception cref="T:System.NotSupportedException">The <see cref="T:System.Collections.Specialized.StringDictionary" /> is read-only.</exception>
            public virtual void Clear() => this.contents.Clear();
            /// <summary>Determines if the <see cref="T:System.Collections.Specialized.StringDictionary" /> contains a specific key.</summary>
            /// <param name="key">The key to locate in the <see cref="T:System.Collections.Specialized.StringDictionary" />.</param>
            /// <returns>
            /// <see langword="true" /> if the <see cref="T:System.Collections.Specialized.StringDictionary" /> contains an entry with the specified key; otherwise, <see langword="false" />.</returns>
            /// <exception cref="T:System.ArgumentNullException">The key is <see langword="null" />.</exception>
            public virtual bool ContainsKey(string key)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                return this.contents.ContainsKey((object)key.ToLower(CultureInfo.InvariantCulture));
            }
            /// <summary>Determines if the <see cref="T:System.Collections.Specialized.StringDictionary" /> contains a specific value.</summary>
            /// <param name="value">The value to locate in the <see cref="T:System.Collections.Specialized.StringDictionary" />. The value can be <see langword="null" />.</param>
            /// <returns>
            /// <see langword="true" /> if the <see cref="T:System.Collections.Specialized.StringDictionary" /> contains an element with the specified value; otherwise, <see langword="false" />.</returns>
            public virtual bool ContainsValue(string value) => this.contents.ContainsValue((object)value);
            /// <summary>Copies the string dictionary values to a one-dimensional <see cref="T:System.Array" /> instance at the specified index.</summary>
            /// <param name="array">The one-dimensional <see cref="T:System.Array" /> that is the destination of the values copied from the <see cref="T:System.Collections.Specialized.StringDictionary" />.</param>
            /// <param name="index">The index in the array where copying begins.</param>
            /// <exception cref="T:System.ArgumentException">
            ///         <paramref name="array" /> is multidimensional.
            /// -or-
            /// The number of elements in the <see cref="T:System.Collections.Specialized.StringDictionary" /> is greater than the available space from <paramref name="index" /> to the end of <paramref name="array" />.</exception>
            /// <exception cref="T:System.ArgumentNullException">
            /// <paramref name="array" /> is <see langword="null" />.</exception>
            /// <exception cref="T:System.ArgumentOutOfRangeException">
            /// <paramref name="index" /> is less than the lower bound of <paramref name="array" />.</exception>
            public virtual void CopyTo(Array array, int index) => this.contents.CopyTo(array, index);
            /// <summary>Returns an enumerator that iterates through the string dictionary.</summary>
            /// <returns>An <see cref="T:System.Collections.IEnumerator" /> that iterates through the string dictionary.</returns>
            public virtual IEnumerator GetEnumerator() => (IEnumerator)this.contents.GetEnumerator();
            /// <summary>Removes the entry with the specified key from the string dictionary.</summary>
            /// <param name="key">The key of the entry to remove.</param>
            /// <exception cref="T:System.ArgumentNullException">The key is <see langword="null" />.</exception>
            /// <exception cref="T:System.NotSupportedException">The <see cref="T:System.Collections.Specialized.StringDictionary" /> is read-only.</exception>
            public virtual void Remove(string key)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                this.contents.Remove((object)key.ToLower(CultureInfo.InvariantCulture));
            }
            internal void ReplaceHashtable(Hashtable useThisHashtableInstead) => this.contents = useThisHashtableInstead;
            internal IDictionary<string, string> AsGenericDictionary() => (IDictionary<string, string>)new StringDictionary.GenericAdapter(this);

            private class GenericAdapter : IDictionary<string, string>, ICollection<KeyValuePair<string, string>>, IEnumerable<KeyValuePair<string, string>>, IEnumerable
            {
                private StringDictionary m_stringDictionary;
                private StringDictionary.GenericAdapter.ICollectionToGenericCollectionAdapter _values;
                private StringDictionary.GenericAdapter.ICollectionToGenericCollectionAdapter _keys;
                internal GenericAdapter(StringDictionary stringDictionary) => this.m_stringDictionary = stringDictionary;
                public void Add(string key, string value) => this[key] = value;
                public bool ContainsKey(string key) => this.m_stringDictionary.ContainsKey(key);
                public void Clear() => this.m_stringDictionary.Clear();
                public int Count => this.m_stringDictionary.Count;
                public string this[string key]
                {
                    get
                    {
                        if (key == null) throw new ArgumentNullException(nameof(key));
                        return this.m_stringDictionary.ContainsKey(key) ? this.m_stringDictionary[key] : throw new KeyNotFoundException();
                    }
                    set
                    {
                        if (key == null) throw new ArgumentNullException(nameof(key));
                        this.m_stringDictionary[key] = value;
                    }
                }
                public ICollection<string> Keys
                {
                    get
                    {
                        if (this._keys == null)
                            this._keys = new StringDictionary.GenericAdapter.ICollectionToGenericCollectionAdapter(this.m_stringDictionary, StringDictionary.GenericAdapter.KeyOrValue.Key);
                        return (ICollection<string>)this._keys;
                    }
                }
                public ICollection<string> Values
                {
                    get
                    {
                        if (this._values == null)
                            this._values = new StringDictionary.GenericAdapter.ICollectionToGenericCollectionAdapter(this.m_stringDictionary, StringDictionary.GenericAdapter.KeyOrValue.Value);
                        return (ICollection<string>)this._values;
                    }
                }
                public bool Remove(string key)
                {
                    if (!this.m_stringDictionary.ContainsKey(key)) return false;
                    this.m_stringDictionary.Remove(key);
                    return true;
                }
                public bool TryGetValue(string key, out string value)
                {
                    if (!this.m_stringDictionary.ContainsKey(key))
                    {
                        value = (string)null;
                        return false;
                    }
                    value = this.m_stringDictionary[key];
                    return true;
                }
                void ICollection<KeyValuePair<string, string>>.Add(KeyValuePair<string, string> item) => this.m_stringDictionary.Add(item.Key, item.Value);
                bool ICollection<KeyValuePair<string, string>>.Contains(KeyValuePair<string, string> item)
                {
                    string str;
                    return this.TryGetValue(item.Key, out str) && str.Equals(item.Value);
                }
                void ICollection<KeyValuePair<string, string>>.CopyTo(KeyValuePair<string, string>[] array, int arrayIndex)
                {
                    if (array == null) throw new ArgumentNullException(nameof(array), "ArgumentNull_Array");
                    if (arrayIndex < 0) throw new ArgumentOutOfRangeException(nameof(arrayIndex), "ArgumentOutOfRange_NeedNonNegNum");
                    if (array.Length - arrayIndex < this.Count) throw new ArgumentException("Arg_ArrayPlusOffTooSmall");
                    int num = arrayIndex;
                    foreach (DictionaryEntry dictionaryEntry in this.m_stringDictionary) array[num++] = new KeyValuePair<string, string>((string)dictionaryEntry.Key, (string)dictionaryEntry.Value);
                }
                bool ICollection<KeyValuePair<string, string>>.IsReadOnly => false;
                bool ICollection<KeyValuePair<string, string>>.Remove(KeyValuePair<string, string> item)
                {
                    if (!((ICollection<KeyValuePair<string, string>>)this).Contains(item)) return false;
                    this.m_stringDictionary.Remove(item.Key);
                    return true;
                }
                IEnumerator IEnumerable.GetEnumerator() => (IEnumerator)this.GetEnumerator();
                public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
                {
                    foreach (DictionaryEntry dictionaryEntry in this.m_stringDictionary) yield return new KeyValuePair<string, string>((string)dictionaryEntry.Key, (string)dictionaryEntry.Value);
                }

                internal enum KeyOrValue
                {
                    Key,
                    Value,
                }

                private class ICollectionToGenericCollectionAdapter : ICollection<string>, IEnumerable<string>, IEnumerable
                {
                    private StringDictionary _internal;
                    private StringDictionary.GenericAdapter.KeyOrValue _keyOrValue;
                    public ICollectionToGenericCollectionAdapter(StringDictionary source, StringDictionary.GenericAdapter.KeyOrValue keyOrValue)
                    {
                        this._internal = source != null ? source : throw new ArgumentNullException(nameof(source));
                        this._keyOrValue = keyOrValue;
                    }
                    public void Add(string item) => this.ThrowNotSupportedException();
                    public void Clear() => this.ThrowNotSupportedException();
                    public void ThrowNotSupportedException()
                    {
                        if (this._keyOrValue == StringDictionary.GenericAdapter.KeyOrValue.Key) throw new NotSupportedException("NotSupported_KeyCollectionSet");
                        throw new NotSupportedException("NotSupported_ValueCollectionSet");
                    }
                    public bool Contains(string item) => this._keyOrValue == StringDictionary.GenericAdapter.KeyOrValue.Key ? this._internal.ContainsKey(item) : this._internal.ContainsValue(item);
                    public void CopyTo(string[] array, int arrayIndex) => this.GetUnderlyingCollection().CopyTo((Array)array, arrayIndex);
                    public int Count => this._internal.Count;
                    public bool IsReadOnly => true;
                    public bool Remove(string item)
                    {
                        this.ThrowNotSupportedException();
                        return false;
                    }
                    private ICollection GetUnderlyingCollection() => this._keyOrValue == StringDictionary.GenericAdapter.KeyOrValue.Key ? this._internal.Keys : this._internal.Values;
                    public IEnumerator<string> GetEnumerator()
                    {
                        foreach (string underlying in (IEnumerable)this.GetUnderlyingCollection()) yield return underlying;
                    }
                    IEnumerator IEnumerable.GetEnumerator() => this.GetUnderlyingCollection().GetEnumerator();
                }
            }
        }
    }
}
