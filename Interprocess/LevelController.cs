using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using JetBrains.Annotations;
using ThreadState = System.Diagnostics.ThreadState;
using Core;

namespace Interprocess
{
    public partial class InterLink
    {
        private static class LevelController
        {
            #region Registration
            
            private static readonly ConcurrentDictionary<InternalLevel, (int ProcessID, Func<string, int> LaunchCode, Mode StartingMode, int HostPID)> _registrations = new ConcurrentDictionary<InternalLevel, (int ProcessID, Func<string, int> LaunchCode, Mode StartingMode, int HostPID)>();

            public static void Register(InternalLevel level, int processID, [CanBeNull] Func<string, int> launchCode = null, Mode startingMode = Mode.TwoWay, int hostPid = -1)
            {
                _registrations.AddOrUpdate(level, _ => (processID, launchCode, startingMode, hostPid), (_, existing) => (processID, launchCode, startingMode, hostPid));
                Open(level);
            }
            public static void Unregister(InternalLevel level)
            {
                _registrations.TryRemove(level, out _);
                Close(level);
            }

            public static (InternalLevel Level, int ProcessID)[] GetRegisteredNodes() => _registrations.Select(x => (x.Key, x.Value.ProcessID)).ToArray();

            #endregion

            #region Open/close controls

            private static readonly ConcurrentDictionary<InternalLevel, (object Lock, CancellationTokenSource CancellationToken)> _closeTokens 
                = new ConcurrentDictionary<InternalLevel, (object Lock, CancellationTokenSource CancellationToken)>();

            [NotNull]
            public static void Open(InternalLevel level)
            {
                _closeTokens.AddOrUpdate(
                    level,
                    _ => (new object(), new CancellationTokenSource()),
                    (_, oldTuple) =>
                    {
                        lock (oldTuple.Lock)
                        {
                            oldTuple.CancellationToken.Dispose();
                            return (new object(), new CancellationTokenSource());
                        }
                    });
            }

            [NotNull]
            public static CancellationToken GetCloseToken(InternalLevel level)
            {
                var tuple = _closeTokens.GetOrAdd(level, _ =>
                {
                    var cts = new CancellationTokenSource();
                    cts.Cancel();
                    return (new object(), cts);
                });

                lock (tuple.Lock)
                    return tuple.CancellationToken.Token;
            }

            public static void Close(InternalLevel level)
            {
                var tuple = _closeTokens.GetOrAdd(level, _ => (new object(), new CancellationTokenSource()));

                lock (tuple.Lock)
                    tuple.CancellationToken.Cancel();
            }
            
            [NotNull]
            public static bool IsClosed(InternalLevel level)
            {
                var tuple = _closeTokens.GetOrAdd(level, _ =>
                {
                    var cts = new CancellationTokenSource();
                    cts.Cancel();
                    return (new object(), cts);
                });

                lock (tuple.Lock)
                    return tuple.CancellationToken.IsCancellationRequested;
            }

            private static readonly object _nodeCheckLock = new object();
            public static void ThrowIfClosedOrExited(InternalLevel level, bool relaunchIfExited)
            {
                if (!_registrations.TryGetValue(level, out var registrationInfo))
                    throw new SecurityException($"Node of level '{level}' has not been registered.");

                lock (_nodeCheckLock)
                {
                    if (IsClosed(level))
                        throw new OperationCanceledException($"InternalLevel {level} is closed.");

                    using var handle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, registrationInfo.ProcessID);
                    bool hasExited = handle.IsInvalid;

                    if (hasExited)
                    {
                        if (registrationInfo.LaunchCode == null || !relaunchIfExited || Tasks.Values.Count(x => x.TargetLevel == level) > 1)
                        {
                            foreach (var message in Tasks.Values.Where(x => x.TargetLevel == level))
                                SetMessageResult(message, null, senderException ?? new ApplicationException($"Node '{level}' exited unexpectedly."));
                            OnNodeExit(level, registrationInfo.ProcessID, 2004);
                            throw new SecurityException($"Node of level '{level}' has exited.");
                        }

                        try
                        {
                            _registrations.TryRemove(level, out _);
                            LaunchNode(registrationInfo.LaunchCode, level.ToLevel(), registrationInfo.StartingMode, registrationInfo.HostPID, true);
                            if (!_registrations.TryGetValue(level, out registrationInfo))
                                throw new SecurityException($"Node level '{level}' relaunch re-registration failed.");
                        }
                        catch (Exception e)
                        {
                            foreach (var message in Tasks.Values.Where(x => x.TargetLevel == level))
                                SetMessageResult(message, null, senderException ?? e);
                            Log.EnqueueExceptionSafe(e);
                            OnNodeExit(level, registrationInfo.ProcessID, 2003);
                            throw;
                        }
                    }

                    var currentExe = Win32.ProcessEx.GetCurrentProcessFileLocation();
                    var levelExe = Win32.ProcessEx.GetProcessFileLocation(registrationInfo.ProcessID);
                    if (levelExe != currentExe)
                    {
                        Log.EnqueueSafe(LogType.Error, "Path mismatch.", new SerializableTrace(), null, ($"{level} Path: ", levelExe), ($"Current Path: ", currentExe));
                        foreach (var message in Tasks.Values.Where(x => x.TargetLevel == level))
                            SetMessageResult(message, null, senderException ?? new ApplicationException($"Node '{level}' path mismatch."));
                        OnNodeExit(level, registrationInfo.ProcessID, 2002);
                        throw new SecurityException("Process path mismatch.");
                    }
                }
            }


            
            #endregion
        }
    }
}