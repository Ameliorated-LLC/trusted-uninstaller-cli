using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Win32.SafeHandles;
using Core;
using Core.Miscellaneous;
using Expression = System.Linq.Expressions.Expression;
using PipeOptions = System.IO.Pipes.PipeOptions;

namespace Interprocess
{
    #region Enums

    public enum Mode
    {
        SendOnly,
        ReceiveOnly,
        TwoWay
    }

    public enum ConnectionAction
    {
        /// <summary>
        /// Terminates the process.
        /// </summary>
        Exit,

        /// <summary>
        /// Pauses all connections, except incoming Progress reports and ShortMessages
        /// </summary>
        Pause,

        /// <summary>
        /// Permanently closes both incoming and outgoing connections.
        /// </summary>
        Close,
    }

    #endregion

    public static partial class InterLink
    {
        // 10MB
        private const int MaxMessageSize = 1024 * 1024 * 100;
        private const string PipePrefix = @"AME";
        
        public static InternalLevel ApplicationLevel { get; private set; } = InternalLevel.Uninitialized;
        private static Mode _mode;
        private static int _hostPID = -1;

        #region Public Controls
        
        private static readonly object _launchLock = new object();

        /// <summary>
        /// Launches a node.
        /// </summary>
        /// <param name="parentLevel">The level that should run <b>launchMethod</b>.</param>
        /// <param name="launchMethod">The method used to launch the node.</param>
        /// <param name="level">The level of the node to launch.</param>
        /// <param name="mode">The mode in which the node should run.</param>
        /// <param name="hostPid">An optional PID of a host to monitor.</param>
        /// <param name="allowAutoRelaunch">Specifies whether or not the node can be relaunched if it exits unexpectedly.<br/><br/>
        /// <b>NOTE: </b>This can only happen if <b>parentLevel</b> tries to execute a method on <b>level</b>.</param>
        /// <returns>The process ID of the launched node.</returns>
        public static int LaunchNode(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Level level, Mode mode, int hostPid, bool allowAutoRelaunch)
        {
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Cannot launch node when connection has not been initialized.");
            if (level == Level.Any || level == Level.Disposable)
                throw new InvalidOperationException($"{level} is not a valid for a node shutdowm.");

            lock (_launchLock)
            {
                var nodes = LevelController.GetRegisteredNodes();
                var arguments = $"\"{Directory.GetCurrentDirectory()}\" Interprocess {level.ToString()} --Mode {mode.ToString()} --Nodes {$"Level={ApplicationLevel}:ProcessID={Process.GetCurrentProcess().Id}" + (nodes.Length > 0 ? "," : string.Empty) + string.Join(",", nodes.Select(x => $"Level={x.Level}:ProcessID={x.ProcessID}"))}" + (hostPid != -1 ? $" --Host {hostPid}" : string.Empty);

                var message = GetLambdaMessage(() => LaunchNode(GetLambdaMessage(launchMethod, parentLevel, arguments), level, ApplicationLevel, mode, hostPid, allowAutoRelaunch), parentLevel);
                ExecuteCore(message);

                try
                {
                    if (!message.Processed.Wait(30000))
                        SetMessageResult(message, null, new TimeoutException($"Timeout reached (30000)."));
                }
                catch (OperationCanceledException e)
                {
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                    ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
                }

                if (message.Result.Exception != null)
                {
                    if (message.Result.Exception.WasDeserialized)
                        message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                    Log.EnqueueExceptionSafe(message.Result.Exception);
                    ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
                }

                var processId = (int)message.Result.Value!.Value!;
                SafeTask.Run(() =>
                {
                    uint exitCode = 258;
                    using var handle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, processId);
                    if (handle.IsInvalid)
                        Log.EnqueueExceptionSafe(new Win32Exception());
                    else
                    {
                        while (Win32.Process.GetExitCodeProcess(handle, out exitCode) && exitCode == 259)
                            Thread.Sleep(250);
                    }

                    OnNodeExit(level.ToInternalLevel(), processId, exitCode);
                    CancelPendingOperations(level.ToTargetLevel(), new ApplicationException($"{level} node exited unexpectedly with exit code: " + exitCode));
                }, true);
                LevelController.Register(level.ToInternalLevel(), processId, null, mode, hostPid);
                return processId;
            }
        }

        [InterprocessMethod(Level.Any)]
        private static int LaunchNode(MethodMessage launchMethod, Level level, InternalLevel caller, Mode mode, int hostPid, bool allowAutoRelaunch)
        {
            var method = launchMethod.Method.ParentClass.Type.GetMethod(launchMethod.Method.MethodName, BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Public, null, launchMethod.Method.Parameters.Select(x => x.Type.Type).ToArray(), null)!;

            ThrowIfUnauthorizedMethodAccess(method, ApplicationLevel.ToTargetLevel(), caller);
            
            var launchCode = (Func<string, int>)(_ => (int)method.Invoke(null, launchMethod.Method.Parameters.Select(x => x.Value).ToArray()));
            var processId = launchCode.Invoke(null);
            
            SafeTask.Run(() =>
            {
                uint exitCode = 258;
                using var handle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, processId);
                if (handle.IsInvalid)
                    Log.EnqueueExceptionSafe(new Win32Exception());
                else
                {
                    while (Win32.Process.GetExitCodeProcess(handle, out exitCode) && exitCode == 259)
                        Thread.Sleep(250);
                }

                OnNodeExit(level.ToInternalLevel(), processId, exitCode);
                CancelPendingOperations(level.ToTargetLevel(), new ApplicationException($"{level} node exited unexpectedly with exit code: " + exitCode));
            }, true);
            LevelController.Register(level.ToInternalLevel(), processId, allowAutoRelaunch ? launchCode : null, mode, hostPid);
            return processId;
        }
        
        public static int LaunchNode(Func<string, int> launchCode, Level level, Mode mode, int hostPid, bool allowAutoRelaunch)
        {
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Cannot launch node when connection has not been initialized.");
            if (level == Level.Any || level == Level.Disposable)
                throw new InvalidOperationException($"{level} is not a valid for a node shutdowm.");

            lock (_launchLock)
            {
                var nodes = LevelController.GetRegisteredNodes();

                var arguments = $"\"{Directory.GetCurrentDirectory()}\" Interprocess {level.ToString()} --Mode {mode.ToString()} --Nodes {$"Level={ApplicationLevel}:ProcessID={Process.GetCurrentProcess().Id}" + (nodes.Length > 0 ? "," : string.Empty) + string.Join(",", nodes.Select(x => $"Level={x.Level}:ProcessID={x.ProcessID}"))}" + (hostPid != -1 ? $" --Host {hostPid}" : string.Empty);
                var processId = launchCode.Invoke(arguments);
                
                SafeTask.Run(() =>
                {
                    uint exitCode = 258;
                    using var handle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, processId);
                    if (handle.IsInvalid)
                        Log.EnqueueExceptionSafe(new Win32Exception());
                    else
                    {
                        while (Win32.Process.GetExitCodeProcess(handle, out exitCode) && exitCode == 259)
                            Thread.Sleep(250);
                    }

                    OnNodeExit(level.ToInternalLevel(), processId, exitCode);
                    CancelPendingOperations(level.ToTargetLevel(), new ApplicationException($"{level} node exited unexpectedly with exit code: " + exitCode));
                }, true);
                LevelController.Register(level.ToInternalLevel(), processId, allowAutoRelaunch ? launchCode : null, mode, hostPid);
                return processId;
            }
        }

        public static void ShutdownNode(Level nodeLevel)
        {
            if (nodeLevel == Level.Any || nodeLevel == Level.Disposable)
                throw new InvalidOperationException($"{nodeLevel} is not a valid for a node shutdowm.");

            LevelController.Unregister(nodeLevel.ToInternalLevel());
            MessageWriteQueue.Add(new ShutdownMessage(nodeLevel.ToInternalLevel(), ApplicationLevel));
        }

        public static void ChangeMode(Mode mode) => _mode = mode;

        public static void RegisterDangerous(Level level, int processId)
        {
            // Exception check
            level.ToTargetLevel();

            SafeTask.Run(() =>
            {
                uint exitCode = 258;
                using var handle = Win32.Process.OpenProcess(Win32.Process.ProcessAccessFlags.QueryLimitedInformation, false, processId);
                if (handle.IsInvalid)
                    Log.EnqueueExceptionSafe(new Win32Exception());
                else
                {
                    while (Win32.Process.GetExitCodeProcess(handle, out exitCode) && exitCode == 259)
                        Thread.Sleep(250);
                }

                OnNodeExit(level.ToInternalLevel(), processId, exitCode);
                CancelPendingOperations(level.ToTargetLevel(), new ApplicationException($"{level} node exited unexpectedly with exit code: " + exitCode));
            }, true);
            LevelController.Register(level.ToInternalLevel(), processId);
        }
        
        public static void SendText(TargetLevel level, string text, int millisecondsTimeout = 1000)
        {
            var textMessage = new TextMessage(level.ToInternalLevel(), ApplicationLevel)
            {
                Text = text,
            };

            MessageWriteQueue.Add(textMessage);
            if (!textMessage.Processed.Wait(millisecondsTimeout))
            {
                SetMessageResult(textMessage, null, new TimeoutException());
                throw new TimeoutException();
            }

            if (textMessage.Result.Exception != null)
                ExceptionDispatchInfo.Capture(textMessage.Result.Exception).Throw();
        }

        public static void CancelPendingOperations(TargetLevel level, [NotNull] Exception exception)
        {
            foreach (var task in Tasks.Values.Where(x => x.Sent && x.TargetLevel == level.ToInternalLevel()))
                SetMessageResult(task, null, exception);
        }

        [ItemCanBeNull]
        public static Task<Exception> SendTextSafe(TargetLevel level, string text, int millisecondsTimeout = 1000) => Wrap.ExecuteSafeAsync(token => SendTextAsync(level, text, millisecondsTimeout));

        public static async Task SendTextAsync(TargetLevel level, string text, int millisecondsTimeout = 1000)
        {
            var textMessage = new TextMessage(level.ToInternalLevel(), ApplicationLevel)
            {
                Text = text,
            };

            MessageWriteQueue.Add(textMessage);
            if (!await textMessage.Processed.WaitAsync(millisecondsTimeout))
            {
                SetMessageResult(textMessage, null, new TimeoutException());
                throw new TimeoutException();
            }

            if (textMessage.Result.Exception != null)
                ExceptionDispatchInfo.Capture(textMessage.Result.Exception).Throw();
        }

        [ItemCanBeNull]
        public static Task<Exception> SendTextAsyncSafe(TargetLevel level, string text, int millisecondsTimeout = 1000) => Wrap.ExecuteSafeAsync(token => SendTextAsync(level, text, millisecondsTimeout));
        
        #endregion

        #region Events

        public static event EventHandler<string> TextReceived;
        public static event EventHandler<Level> NodeExitedUnexpectedly;
        public static event EventHandler<Level> NodeRegistered;
        
        #endregion
        
        #region Initializer

        public static async Task InitializeConnection(Level level, Mode mode, int host, (Interprocess.InterLink.InternalLevel Level, int ProcessID)[] nodes)
        {
            if (nodes != null)
                foreach (var node in nodes)
                    Wrap.ExecuteSafe(() => LevelController.Register(node.Level, node.ProcessID), true);

            await InitializeConnection(level, mode, host);
            verificationThread.Join();
            Environment.Exit(-4);
        }

        public static async Task InitializeConnection(Level currentLevel, Mode mode, int hostPid = -1)
        {
            if (ApplicationLevel != InternalLevel.Uninitialized)
                throw new InvalidOperationException("Cannot initialize connection twice.");
            if (senderCancel.IsCancellationRequested || receiverCancel.IsCancellationRequested)
                throw new InvalidOperationException("Cannot initialize connection after a cancellation. Use Pause() or Unpause() to control communication.");

            ApplicationLevel = currentLevel.ToInternalLevel();
            _mode = mode;
            
            Log.CurrentSource = currentLevel + " Node";

            Process host;
            try
            {
                host = hostPid == -1 ? null : Process.GetProcessById(hostPid);
            }
            catch (ArgumentException e)
            {
                Log.EnqueueExceptionSafe(e);
                Environment.Exit(-11);
                return;
            }
            _hostPID = hostPid;
            
            var pipeSecurity = new PipeSecurity();

            var adminRule = new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.Read | PipeAccessRights.Synchronize | PipeAccessRights.Write, AccessControlType.Allow);
            pipeSecurity.SetAccessRule(adminRule);

            // .NET 8: Remove async since we don't need to prep the serializer due to Source Generation.
            await Task.Run(() =>
            {
                JsonSerializer.Deserialize<MethodMessage>(JsonSerializer.Serialize(new MethodMessage(InternalLevel.User, InternalLevel.Administrator) {Method = new SerializableMethod()}, _serializerOptions), _serializerOptions);
                JsonSerializer.Deserialize<MessageResult>(JsonSerializer.Serialize(new MessageResult(Guid.Empty, InternalLevel.User, InternalLevel.Administrator, new Serializables.SerializableValue(typeof(string), "Test")), _serializerOptions), _serializerOptions);
                JsonSerializer.Deserialize<VerificationRequest>(JsonSerializer.Serialize(new VerificationRequest() { CallerLevel = InternalLevel.User, IdToVerify = new Guid(), JsonHash = new byte[] { }, TargetLevel = InternalLevel.Administrator, Type = VerificationType.Message }, _serializerOptions), _serializerOptions);
            });
            
            verificationThread = new Thread(() => VerificationThread(pipeSecurity)) { CurrentUICulture = CultureInfo.InvariantCulture, IsBackground = true };
            verificationThread.Start();

            sendResultThread = new Thread(SendResultThread) { CurrentUICulture = CultureInfo.InvariantCulture, IsBackground = true };
            sendResultThread.Start();
            senderThread = new Thread(SenderThread) { CurrentUICulture = CultureInfo.InvariantCulture, IsBackground = true };
            senderThread.Start();

            receiveResultThread = new Thread(() => ReceiveResultThread(pipeSecurity)) { CurrentUICulture = CultureInfo.InvariantCulture, IsBackground = true };
            receiveResultThread.Start();
            receiverThread = new Thread(() => ReceiverThread(pipeSecurity)) { CurrentUICulture = CultureInfo.InvariantCulture, IsBackground = true };
            receiverThread.Start();
            
            while (!host?.HasExited ?? false)
            {
                host.WaitForExit();
                Thread.Sleep(100);
            }
            
            if (host != null)
                Environment.Exit(-10);
        }

        public static void CloseConnection(bool waitForExit)
        {
            CancelReceiver();
            CancelSender();

            if (waitForExit &&
                (!senderThread.Join(250) || !sendResultThread.Join(250) ||
                 !receiverThread.Join(250) || !receiveResultThread.Join(250)))
                throw new TimeoutException("Connection took too long to close.");
        }

        public static async Task RegisterToTarget(TargetLevel level)
        {
            if (level == TargetLevel.Auto || level == TargetLevel.Disposable)
                throw new InvalidOperationException($"{level} is not a valid registration target.");
            if (level.ToInternalLevel() == ApplicationLevel)
                throw new InvalidOperationException("Cannot register to self.");

            var message = new NodeRegistrationMessage(level.ToInternalLevel(), ApplicationLevel)
            {
                Level = ApplicationLevel,
                ProcessID = Process.GetCurrentProcess().Id,
            };
            MessageWriteQueue.Add(message);

            if (!await message.Processed.WaitAsync(500))
            {
                SetMessageResult(message, null, new TimeoutException());
                throw new TimeoutException("Registration timed out.");
            }

            if (message.Result.Exception != null)
                throw message.Result.Exception;
            
            var response = (int)message.Result.Value!.Value!;
            LevelController.Register(level.ToInternalLevel(), response);
        }

        #endregion

        #region Public Execution Methods

        public static void EnqueueSafe(Expression<Func<Task>> operation, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, TargetLevel.Auto, enqueueTimeout, logExceptions);
        public static void EnqueueSafe<TResult>(Expression<Func<Task<TResult>>> operation, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, TargetLevel.Auto, enqueueTimeout, logExceptions);
        public static void EnqueueSafe<TResult>(Expression<Func<TResult>> operation, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, TargetLevel.Auto, enqueueTimeout, logExceptions);
        public static void EnqueueSafe(Expression<Action> operation, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, TargetLevel.Auto, enqueueTimeout, logExceptions);
        public static void EnqueueSafe(Expression<Func<Task>> operation, TargetLevel level, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, level, enqueueTimeout, logExceptions);
        public static void EnqueueSafe<TResult>(Expression<Func<Task<TResult>>> operation, TargetLevel level, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, level, enqueueTimeout, logExceptions);
        public static void EnqueueSafe<TResult>(Expression<Func<TResult>> operation, TargetLevel level, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, level, enqueueTimeout, logExceptions);
        public static void EnqueueSafe(Expression<Action> operation, TargetLevel level, int enqueueTimeout, bool logExceptions) => EnqueueSafeCore(operation, level, enqueueTimeout, logExceptions);
        private static void EnqueueSafeCore(Expression operation, TargetLevel level, int enqueueTimeout, bool logExceptions)
        {
            if (enqueueTimeout < 1)
                throw new ArgumentException($"{nameof(enqueueTimeout)} must be greater than 0.", nameof(enqueueTimeout));
            
            var message = GetLambdaMessageCore(operation, level);
            message.EnqueueTimeout = enqueueTimeout;
            message.Enqueued = true;
            message.LogExceptions = logExceptions;
            ExecuteCore(message);
        }

        public static Wrap.SafeResult<TResult> ExecuteSafe<TResult>(Expression<Func<TResult>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafe(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Wrap.SafeResult<TResult> ExecuteSafe<TResult>(Expression<Func<TResult>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafe(() => Execute(operation, level, logExceptions, timeout));
        public static TResult Execute<TResult>(Expression<Func<TResult>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => Execute(operation, TargetLevel.Auto, logExceptions, timeout);
        public static TResult Execute<TResult>(Expression<Func<TResult>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!message.Processed.Wait(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
            }

            return message.Result.Value == null ? default(TResult) : (TResult)message.Result.Value.Value;
        }

        public static Wrap.SafeResult<TResult> ExecuteSafe<TResult>(Expression<Func<Task<TResult>>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafe(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Wrap.SafeResult<TResult> ExecuteSafe<TResult>(Expression<Func<Task<TResult>>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafe(() => Execute(operation, level, logExceptions, timeout));
        public static TResult Execute<TResult>(Expression<Func<Task<TResult>>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => Execute(operation, TargetLevel.Auto, logExceptions, timeout);
        public static TResult Execute<TResult>(Expression<Func<Task<TResult>>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!message.Processed.Wait(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
            }

            return message.Result.Value == null ? default(TResult) : (TResult)message.Result.Value.Value;
        }

        public static Task<Wrap.SafeResult<TResult>> ExecuteSafeAsync<TResult>(Expression<Func<TResult>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafeAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Task<Wrap.SafeResult<TResult>> ExecuteSafeAsync<TResult>(Expression<Func<TResult>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafeAsync(async token => await ExecuteAsync(operation, level, logExceptions, timeout));
        public static Task<TResult> ExecuteAsync<TResult>(Expression<Func<TResult>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static async Task<TResult> ExecuteAsync<TResult>(Expression<Func<TResult>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!await message.Processed.WaitAsync(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
                return default;
            }

            return message.Result.Value == null ? default : (TResult)message.Result.Value.Value;
        }

        public static Task<Wrap.SafeResult<TResult>> ExecuteSafeAsync<TResult>(Expression<Func<Task<TResult>>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafeAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Task<Wrap.SafeResult<TResult>> ExecuteSafeAsync<TResult>(Expression<Func<Task<TResult>>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafeAsync(async token => await ExecuteAsync(operation, level, logExceptions, timeout));
        public static Task<TResult> ExecuteAsync<TResult>(Expression<Func<Task<TResult>>> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static async Task<TResult> ExecuteAsync<TResult>(Expression<Func<Task<TResult>>> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!await message.Processed.WaitAsync(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
                return default;
            }

            return message.Result.Value == null ? default : (TResult)message.Result.Value.Value;
        }

        public static Exception ExecuteSafe(Expression<Action> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafe(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Exception ExecuteSafe(Expression<Action> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafe(() => Execute(operation, level, logExceptions, timeout));
        public static void Execute(Expression<Action> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => Execute(operation, TargetLevel.Auto, logExceptions, timeout);
        public static void Execute(Expression<Action> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!message.Processed.Wait(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
            }
        }

        public static Task<Exception> ExecuteSafeAsync(Expression<Action> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteSafeAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static Task<Exception> ExecuteSafeAsync(Expression<Action> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite) => Wrap.ExecuteSafeAsync(async token => await ExecuteAsync(operation, level, logExceptions, timeout));
        public static Task ExecuteAsync(Expression<Action> operation, bool logExceptions = false, int timeout = Timeout.Infinite) => ExecuteAsync(operation, TargetLevel.Auto, logExceptions, timeout);
        public static async Task ExecuteAsync(Expression<Action> operation, TargetLevel level, bool logExceptions = false, int timeout = Timeout.Infinite)
        {
            var message = GetLambdaMessage(operation, level);
            ExecuteCore(message);

            try
            {
                if (!await message.Processed.WaitAsync(timeout))
                    SetMessageResult(message, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? e).Throw();
            }

            if (message.Result.Exception != null)
            {
                if (message.Result.Exception.WasDeserialized)
                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                if (logExceptions)
                    Log.EnqueueExceptionSafe(message.Result.Exception);
                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
            }
        }

        #region Disposable

        public static Wrap.SafeResult<TResult> ExecuteDisposableSafe<TResult>(TargetLevel parentLevel, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe(() => ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null));
        public static Wrap.SafeResult<TResult> ExecuteDisposableSafe<TResult>(TargetLevel parentLevel, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe(() => ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null));
        public static Exception ExecuteDisposableSafe(TargetLevel parentLevel, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe((Action)(() => ExecuteDisposableCore<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null)));
        public static Task<Wrap.SafeResult<TResult>> ExecuteDisposableSafeAsync<TResult>(TargetLevel parentLevel, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafeAsync(async token => await ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null));
        public static Task<Wrap.SafeResult<TResult>> ExecuteDisposableSafeAsync<TResult>(TargetLevel parentLevel, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) => 
            Wrap.ExecuteSafeAsync(async token => await ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null));
        public static Task<Exception> ExecuteDisposableSafeAsync(TargetLevel parentLevel, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafeAsync((Func<CancellationToken, Task>)(async token => await ExecuteDisposableCoreAsync<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null)));
        
        public static TResult ExecuteDisposable<TResult>(TargetLevel parentLevel, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        public static TResult ExecuteDisposable<TResult>(TargetLevel parentLevel, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        public static void ExecuteDisposable(TargetLevel parentLevel, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        public static Task<TResult> ExecuteDisposableAsync<TResult>(TargetLevel parentLevel, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        public static Task<TResult> ExecuteDisposableAsync<TResult>(TargetLevel parentLevel, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) => 
            ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        public static async Task ExecuteDisposableAsync(TargetLevel parentLevel, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            await ExecuteDisposableCoreAsync<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, null);
        
        public static Wrap.SafeResult<TResult> ExecuteDisposableSafe<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe(() => ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}")));
        public static Wrap.SafeResult<TResult> ExecuteDisposableSafe<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe(() => ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}")));
        public static Exception ExecuteDisposableSafe(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafe((Action)(() => ExecuteDisposableCore<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"))));
        public static Task<Wrap.SafeResult<TResult>> ExecuteDisposableSafeAsync<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafeAsync(async token => await ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}")));
        public static Task<Wrap.SafeResult<TResult>> ExecuteDisposableSafeAsync<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) => 
            Wrap.ExecuteSafeAsync(async token => await ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}")));
        public static Task<Exception> ExecuteDisposableSafeAsync(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            Wrap.ExecuteSafeAsync((Func<CancellationToken, Task>)(async token => await ExecuteDisposableCoreAsync<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"Interprocess --ActivePath \"{Directory.GetCurrentDirectory()}\" Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"))));
        
        public static TResult ExecuteDisposable<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        public static TResult ExecuteDisposable<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        public static void ExecuteDisposable(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCore<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        public static Task<TResult> ExecuteDisposableAsync<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<TResult>> operation, int timeout = 60000, bool logExceptions = false) =>
            ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        public static Task<TResult> ExecuteDisposableAsync<TResult>(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Func<Task<TResult>>> operation, int timeout = 60000, bool logExceptions = false) => 
            ExecuteDisposableCoreAsync<TResult>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        public static async Task ExecuteDisposableAsync(TargetLevel parentLevel, Expression<Func<string, int>> launchMethod, Expression<Action> operation, int timeout = 60000, bool logExceptions = false) =>
            await ExecuteDisposableCoreAsync<Void>(parentLevel, GetLambdaMessage(operation, parentLevel), timeout, logExceptions, GetLambdaMessage(launchMethod, parentLevel, $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={parentLevel}:ProcessID={(ApplicationLevel == parentLevel.ToInternalLevel() ? Process.GetCurrentProcess().Id : LevelController.GetRegisteredNodes().First(x => x.Level == parentLevel.ToInternalLevel()).ProcessID)} --Host {Process.GetCurrentProcess().Id}"));
        
        #endregion

        #endregion

        internal struct Void { }

        #region Core Execution Methods

        private static TResult ExecuteDisposableCore<TResult>(TargetLevel parentLevel, MethodMessage message, int timeout, bool logExceptions, MethodMessage launchMethod)
        {
            if (parentLevel == TargetLevel.Disposable)
                throw new ArgumentException("Invalid disposable parent level: " + parentLevel, nameof(parentLevel));
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Connection must be initialized to call execution methods.");

            if (parentLevel.ToInternalLevel() == ApplicationLevel)
            {
                return NodeMethods.ExecuteDisposable<TResult>(message, timeout, logExceptions, launchMethod);
            }

            var sendMessage = GetLambdaMessage(() => NodeMethods.ExecuteDisposable<TResult>(message, timeout, logExceptions, launchMethod), parentLevel);
            MessageWriteQueue.Add(sendMessage);

            try
            {
                if (!sendMessage.Processed.Wait(timeout + 5000))
                    SetMessageResult(sendMessage, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(sendMessage.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(sendMessage.Result.Exception ?? senderException ?? e).Throw();
            }

            if (sendMessage.Result.Exception != null)
            {
                if (sendMessage.Result.Exception.WasDeserialized)
                    sendMessage.Result.Exception.Trace.Prepend(new SerializableTrace(null, 1, 3));

                ExceptionDispatchInfo.Capture(sendMessage.Result.Exception).Throw();
            }

            return (TResult)sendMessage.Result.Value!.Value;
        }

        private static async Task<TResult> ExecuteDisposableCoreAsync<TResult>(TargetLevel parentLevel, MethodMessage message, int timeout, bool logExceptions, MethodMessage launchMethod)
        {
            if (parentLevel == TargetLevel.Disposable)
                throw new ArgumentException("Invalid disposable parent level: " + parentLevel, nameof(parentLevel));
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Connection must be initialized to call execution methods.");

            if (parentLevel.ToInternalLevel() == ApplicationLevel)
            {
                return await Task.Run(() => NodeMethods.ExecuteDisposable<TResult>(message, timeout, logExceptions, launchMethod));
            }

            var sendMessage = GetLambdaMessage(() => NodeMethods.ExecuteDisposable<TResult>(message, timeout, logExceptions, launchMethod), parentLevel);
            MessageWriteQueue.Add(sendMessage);

            try
            {
                if (!await sendMessage.Processed.WaitAsync(timeout + 5000))
                    SetMessageResult(sendMessage, null, new TimeoutException($"Timeout reached ({timeout})."));
            }
            catch (OperationCanceledException e)
            {
                if (logExceptions)
                    Log.EnqueueExceptionSafe(sendMessage.Result.Exception ?? senderException ?? e);
                ExceptionDispatchInfo.Capture(sendMessage.Result.Exception ?? senderException ?? e).Throw();
            }

            if (sendMessage.Result.Exception != null)
            {
                if (sendMessage.Result.Exception.WasDeserialized)
                    sendMessage.Result.Exception.Trace.Prepend(new SerializableTrace(null, 1, 3));

                ExceptionDispatchInfo.Capture(sendMessage.Result.Exception).Throw();
            }

            return (TResult)sendMessage.Result.Value!.Value;
        }

        private static void ExecuteCore(MethodMessage message)
        {
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Connection must be initialized to call execution methods.");
            if (message.TargetLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("InternalLevel.Uninitialized is not a valid target level.");
            if (message.CallerLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("InternalLevel.Uninitialized is not a valid caller level.");

            if (_mode == Mode.ReceiveOnly)
                throw new UnauthorizedAccessException("Cannot send a message from a receive-only node.");

            if (message.Method == null)
                throw new InvalidOperationException("InterMessage Method property cannot be null.");

            try
            {
                foreach (var argument in message.Method.Parameters)
                {
                    if (argument.Value != null && typeof(IInterObject).IsAssignableFrom(argument.Type.Type))
                        ((IInterObject)argument.Value).BeforeSend(message.TargetLevel);
                }
            }
            catch (Exception e)
            {
                SetMessageResult(message, null, new SerializableException(e));
            }

            if (message.TargetLevel == ApplicationLevel)
            {
                Task.Run(() =>
                {
                    var result = Wrap.ExecuteSafe(() =>
                    {
                        var result = new Serializables.SerializableValue(message.Method.Method.ReturnType, message.Method.Method.Invoke(null, message.Method.Parameters.Select(x => x.Value).ToArray()));

                        if (result.Value is Task task)
                        {
                            task.GetAwaiter().GetResult();
                            if (task.GetType().IsGenericType)
                            {
                                dynamic taskOfTypeT = task;
                                result = taskOfTypeT.Result == null ? null : new Serializables.SerializableValue(taskOfTypeT.Result.GetType(), taskOfTypeT.Result);
                            }
                        }

                        return result;
                    });

                    if (result.Failed)
                    {
                        if (result.Exception is TargetInvocationException invokeException && invokeException.InnerException != null)
                            SetMessageResult(message, null, new SerializableException(invokeException.InnerException, $"({message.TargetLevel}) " + invokeException.InnerException.Message));
                        else
                            SetMessageResult(message, null, new SerializableException(result.Exception, $"({message.TargetLevel}) " + result.Exception.Message));
                    }
                    else
                        SetMessageResult(message, new MessageResult(new Guid(), message.TargetLevel, message.CallerLevel, result.Value), null);

                    message.Processed.Release();
                });
                return;
            }

            if (senderException != null)
                ExceptionDispatchInfo.Capture(senderException).Throw();

            MessageWriteQueue.Add(message);
        }

        private static MethodMessage GetLambdaMessage<TResult>(Expression<Func<TResult>> expression, TargetLevel targetLevel) => GetLambdaMessageCore(expression, targetLevel);
        private static MethodMessage GetLambdaMessage<TResult>(Expression<Func<Task<TResult>>> expression, TargetLevel targetLevel) => GetLambdaMessageCore(expression, targetLevel);
        private static MethodMessage GetLambdaMessage(Expression<Action> expression, TargetLevel targetLevel) => GetLambdaMessageCore(expression, targetLevel);
        private static MethodMessage GetLambdaMessage<TArg>(Expression<Action<TArg>> expression, TargetLevel targetLevel, TArg argument) => GetLambdaMessageCore(expression, targetLevel, (typeof(TArg), argument));
        private static MethodMessage GetLambdaMessage<TResult, TArg>(Expression<Func<TArg, TResult>> expression, TargetLevel targetLevel, TArg argument) => GetLambdaMessageCore(expression, targetLevel, (typeof(TArg), argument));

        private static MethodMessage GetLambdaMessageCore(Expression expression, TargetLevel targetLevel, params (Type Type, object Value)[] args)
        {
            if (ApplicationLevel == InternalLevel.Uninitialized)
                throw new InvalidOperationException("Connection must be initialized to call execution methods.");
            if (!(expression is LambdaExpression lambdaExpression))
                throw new SerializationException("Unrecognized expression type: " + expression.GetType() + Environment.NewLine + "Lambda expression should call a single function.");
            if (!(lambdaExpression.Body is MethodCallExpression methodExpression))
                throw new InvalidOperationException("Lambda expression must call a single function.");

            var TResult = lambdaExpression.ReturnType;

            if (TResult.IsGenericType && TResult.GetGenericTypeDefinition() == typeof(Task<>))
            {
                // For Task<T>, check if T (i.e. the generic argument) is serializable
                Type taskTypeArgument = TResult.GetGenericArguments()[0];
                if (!IsSerializable(taskTypeArgument))
                    throw new SerializationException($"The task return type '{taskTypeArgument}' must be added as a JsonSerializable.");
            }
            else if (TResult != typeof(Task) && !IsSerializable(TResult))
                throw new SerializationException($"Return type '{TResult}' must be added as a JsonSerializable.");

            var methodInfo = methodExpression.Method;

            if (methodInfo.MemberType != MemberTypes.Method)
                throw new InvalidOperationException("Lambda expression must call a single function.");
            if (!methodInfo.IsStatic)
                throw new InvalidOperationException("Method must be static.");
            
            var internalTargetLevel = ThrowIfUnauthorizedMethodAccess(methodInfo, targetLevel, ApplicationLevel);

            return new MethodMessage(internalTargetLevel, ApplicationLevel)
            {
                Method = new SerializableMethod()
                {
                    MethodName = methodInfo.Name,
                    ParentClass = new Serializables.SerializableType(methodInfo.ReflectedType),
                    Method = methodInfo,
                    GenericTypes = GetGenericArguments(methodInfo),
                    Parameters = GetParameters(methodExpression.Arguments, lambdaExpression.Parameters.ToArray(), args)
                },
            };
        }
        
        private class ReplaceVisitor : ExpressionVisitor
        {
            private readonly string _oldParamName;
            private readonly Expression _newParam;

            public ReplaceVisitor(string oldParamName, Expression newParam) => (_oldParamName, _newParam) = (oldParamName, newParam);
            protected override Expression VisitParameter(ParameterExpression node) => node.Name == _oldParamName ? _newParam : base.VisitParameter(node);

        }

        public static bool IsSerializable(Type type)
        {
            return type == typeof(void) || SourceGenerationContext.Default.GetTypeInfo(type) != null;
        }

        public static Serializables.SerializableType[] GetGenericArguments(MethodInfo method)
        {
            if (!method.IsGenericMethod)
                return Array.Empty<Serializables.SerializableType>();

            return method.GetGenericArguments().Select(arg => new Serializables.SerializableType(arg)).ToArray();
        }

        public static Serializables.SerializableValue[] GetParameters(ReadOnlyCollection<Expression> arguments, ParameterExpression[] parameters, (Type Type, object Value)[] args = null)
        {
            return arguments.Select(arg =>
            {
                if (!IsSerializable(arg.Type))
                    throw new SerializationException($"Argument of type '{arg.Type}' must be added as a JsonSerializable.");
                
                Expression expression = arg;
                if (args != null)
                {
                    if (parameters.Length != args.Length)
                        throw new SerializationException($"The number of parameters ({parameters.Length}) does not match the number of supplied arguments ({args.Length}).");

                    for (var i = 0; i < parameters.Length; i++)
                    {
                        if (parameters[i].Type != args[i].Type)
                            throw new SerializationException($"The parameter type ({parameters[i].Type}) does not match the argument type ({args[i].Type}).");
                        
                        var argExpression = Expression.Constant(args[i].Value, args[i].Type);
                        expression = new ReplaceVisitor(parameters[i].Name, argExpression).Visit(arg);
                    }
                }

                var objectMember = Expression.Convert(expression, typeof(object));
                var getterLambda = Expression.Lambda<Func<object>>(objectMember);

                object value;
                try
                {
                    value = getterLambda.Compile().Invoke();
                }
                catch (Exception e)
                {
                    Log.EnqueueExceptionSafe(e);
                    throw new SerializationException($"Failed to compile parameter of type '{arg.Type}': " + arg.Type + e.Message);
                }
                
                return new Serializables.SerializableValue(arg.Type, value);
            }).ToArray();
        }

        #endregion

        #region Internal node controls

        private static Process LaunchDisposableNode(MethodMessage launchMethod, InternalLevel caller)
        {
            var method = launchMethod.Method.ParentClass.Type.GetMethod(launchMethod.Method.MethodName, BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Public, null, launchMethod.Method.Parameters.Select(x => x.Type.Type).ToArray(), null)!;

            ThrowIfUnauthorizedMethodAccess(method, ApplicationLevel.ToTargetLevel(), caller);
            
            var launchCode = (Func<string, int>)(_ => (int)method.Invoke(null, launchMethod.Method.Parameters.Select(x => x.Value).ToArray()));
            var processId = launchCode.Invoke(null);
            return Process.GetProcessById(processId);
        }
        
        private static Process LaunchDisposableNode()
        {
            var arguments = $"\"{Directory.GetCurrentDirectory()}\" Interprocess Disposable --Mode TwoWay --Nodes Level={ApplicationLevel}:ProcessID={Process.GetCurrentProcess().Id} --Host {Process.GetCurrentProcess().Id}";
            return Process.Start(new ProcessStartInfo(Win32.ProcessEx.GetCurrentProcessFileLocation(), arguments) {UseShellExecute = false, CreateNoWindow = true});
        }

        private static class NodeMethods
        {
            [InterprocessMethod(Level.Any)]
            public static TResult ExecuteDisposable<TResult>(MethodMessage message, int timeout, bool logExceptions, MethodMessage launchMethod)
            {
                using (var mutex = new Mutex(false, "AME-Node-Disposable"))
                {
                    try
                    {
                        if (!mutex.WaitOne(timeout))
                            throw new TimeoutException("Disposable mutex timed out. Make sure no other Disposable nodes are running.");

                        var process = launchMethod == null ? LaunchDisposableNode() : LaunchDisposableNode(launchMethod, ApplicationLevel);

                        using var linkedToken = CancellationTokenSource.CreateLinkedTokenSource(new CancellationToken(), senderCancel.Token);

                        EventHandler handler = (sender, args) => Wrap.ExecuteSafe(() =>
                        {
                            if (process.ExitCode != 0)
                                linkedToken.Cancel();
                        });
                        process.EnableRaisingEvents = true;
                        try
                        {
                            process.Exited += handler;
                            if (process.HasExited)
                                linkedToken.Cancel();

                            message = new MethodMessage(InternalLevel.Disposable, ApplicationLevel)
                            {
                                Method = new SerializableMethod()
                                {
                                    MethodName = message.Method.MethodName,
                                    GenericTypes = message.Method.GenericTypes,
                                    Parameters = message.Method.Parameters,
                                    ParentClass = message.Method.ParentClass,
                                },
                            };
                            MessageWriteQueue.Add(message);

                            try
                            {
                                if (!message.Processed.Wait(timeout, linkedToken.Token))
                                    message.Result.Exception = new SerializableException(new TimeoutException($"Timeout reached ({timeout})."));
                            }
                            catch (OperationCanceledException e)
                            {
                                process.EnableRaisingEvents = false;
                                var killException = Wrap.ExecuteSafe(() =>
                                {
                                    if (!process.HasExited)
                                        process.Kill();
                                });
                                if (killException != null)
                                    Log.EnqueueExceptionSafe(killException);

                                if (logExceptions)
                                    Log.EnqueueExceptionSafe(message.Result.Exception ?? senderException ?? (process.HasExited ? new Exception("Disposable node exited unexpectedly with exit code: " + process.ExitCode) : e));
                                ExceptionDispatchInfo.Capture(message.Result.Exception ?? senderException ?? (process.HasExited ? new Exception("Disposable node exited unexpectedly with exit code: " + process.ExitCode) : e)).Throw();
                            }

                            if (message.Result.Exception != null)
                            {
                                var killException = Wrap.ExecuteSafe(() =>
                                {
                                    if (!process.HasExited)
                                        process.Kill();
                                });
                                if (killException != null)
                                    Log.EnqueueExceptionSafe(killException);

                                if (message.Result.Exception.WasDeserialized)
                                    message.Result.Exception.Trace.Prepend(new SerializableTrace(null, 0, 5));

                                if (logExceptions)
                                    Log.EnqueueExceptionSafe(message.Result.Exception);
                                ExceptionDispatchInfo.Capture(message.Result.Exception).Throw();
                            }

                            if (!process.WaitForExit(5000))
                                throw new TimeoutException("Disposable process took too long to exit.");
                            return typeof(TResult) == typeof(Void) ? default : (TResult)message.Result.Value!.Value;
                        }
                        finally
                        {
                            process.EnableRaisingEvents = false;
                            process.Exited -= handler;
                            process.Dispose();
                        }
                    }
                    finally
                    {
                        mutex.ReleaseMutex();
                    }
                }
            }
        }

        #endregion

        #region Helper Methods
        
        private static void ExitIfHostExited()
        {
            if (_hostPID == -1)
                return;
            
            if (Wrap.ExecuteSafe(() => Process.GetProcessById(_hostPID)).Failed)
                Environment.Exit(-34);
        }

        private static byte[] _synchronizationGuid = new Guid("bd5ae0e5-b7ae-4b9a-a14b-ad8539587d2a").ToByteArray();

        private class ReadJsonResult
        {
            public Guid? MessageID { get; set; } = null;
            public InternalLevel? Caller { get; set; } = null;
            [CanBeNull] public byte[] Json { get; set; } = null;
            [CanBeNull] public Exception Exception { get; set; } = null;
        }
        
        private static ReadJsonResult ReadJson(NamedPipeServerStream pipe, int timeout, CancellationToken token, bool isMessage)
        {
            using (_ = new SynchronousIoCanceler(timeout, token))
            {

                byte[] buffer = new byte[2048];
                Queue<byte> recentBytes = new Queue<byte>();
                int leftoverIndex = 0;

                bool guidFound = false;
                int bytesRead = 0;
                while (!guidFound)
                {
                    bytesRead = pipe.Read(buffer, 0, buffer.Length);

                    if (bytesRead == 0)
                        throw new Exception("The end of the stream was reached without finding the target GUID.");

                    for (int i = 0; i < bytesRead; ++i)
                    {
                        if (recentBytes.Count >= 16)
                            recentBytes.Dequeue();

                        recentBytes.Enqueue(buffer[i]);

                        if (recentBytes.SequenceEqual(_synchronizationGuid))
                        {
                            leftoverIndex = i + 1;
                            guidFound = true;
                            break;
                        }
                    }
                }

                byte[] header = new byte[isMessage ? 24 : 4];
                var sizeBytesLeft = header.Length;
                var bufferSizeLeft = bytesRead - leftoverIndex;

                if (bufferSizeLeft > 0)
                {
                    var bytesToCopy = Math.Min(sizeBytesLeft, bufferSizeLeft);
                    Array.Copy(buffer, leftoverIndex, header, 0, bytesToCopy);
                    sizeBytesLeft -= bytesToCopy;
                    leftoverIndex += bytesToCopy;
                }

                if (sizeBytesLeft > 0)
                    pipe.Read(header, header.Length - sizeBytesLeft, sizeBytesLeft);

                var result = new ReadJsonResult();
                if (isMessage)
                {
                    result.MessageID = new Guid(header.Take(16).ToArray());
                    result.Caller = (InternalLevel)BitConverter.ToInt32(header, 16);
                }

                try
                {
                    int messageLength = BitConverter.ToInt32(header, isMessage ? 20 : 0);
                    if (messageLength > MaxMessageSize)
                        throw new SerializationException($"Received data is more than the maximum message size ({messageLength / 1024}KB > {MaxMessageSize / 1024}KB).");

                    byte[] jsonBuffer = new byte[messageLength];
                    var jsonBytesLeft = jsonBuffer.Length;

                    bufferSizeLeft = bytesRead - leftoverIndex;
                    if (bufferSizeLeft > 0)
                    {
                        var bytesToCopy = Math.Min(jsonBytesLeft, bufferSizeLeft);
                        Array.Copy(buffer, leftoverIndex, jsonBuffer, 0, bytesToCopy);
                        jsonBytesLeft -= bytesToCopy;
                    }
                    
                    if (jsonBytesLeft > 0)
                        pipe.Read(jsonBuffer, jsonBuffer.Length - jsonBytesLeft, jsonBytesLeft);

                    result.Json = jsonBuffer;
                    return result;
                }
                catch (Exception e)
                {
                    if (!isMessage)
                        throw;
                    result.Exception = e;
                    return result;
                }
            }
        }
        
        private static void WriteJson(NamedPipeClientStream pipe, byte[] utf8JsonBytes, int timeout, CancellationToken token, [CanBeNull] InterMessage message)
        {
            byte[] array;
            if (message != null)
                array = CombineByteArrays(_synchronizationGuid, message.MessageID.ToByteArray(), BitConverter.GetBytes((int)message.CallerLevel), BitConverter.GetBytes(utf8JsonBytes.Length), utf8JsonBytes);
            else
                array = CombineByteArrays(_synchronizationGuid, BitConverter.GetBytes(utf8JsonBytes.Length), utf8JsonBytes);

            using (_ = new SynchronousIoCanceler(timeout, token))
                pipe.Write(array, 0, array.Length);
        }

        private static byte[] CombineByteArrays(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays) {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }
        
        private static ConcurrentDictionary<InternalLevel, int> _exits = new ConcurrentDictionary<InternalLevel, int>();
        private static void OnNodeExit(InternalLevel level, int pid, uint exitCode)
        {
            bool alreadyExited = false;
            _exits.AddOrUpdate(level,pid,(_, existingPid) =>
                {
                    alreadyExited = existingPid == pid;
                    return pid;
                });
            if (alreadyExited)
                return;
                
            LevelController.Close(level);
                
            var handler = NodeExitedUnexpectedly;
            if (handler != null)
            {
                foreach (var invoker in handler.GetInvocationList())
                {
                    SafeTask.Run(() => ((EventHandler<Level>)invoker).Invoke(exitCode, level.ToLevel()), true);
                }
            }
        }

        private static void SetMessageResult(InterMessage message, [CanBeNull] MessageResult result, [CanBeNull] Exception exception)
        {
            if (result == null && exception == null)
                throw new ArgumentNullException(null, "Either value or exception must not be null.");

            lock (message)
            {
                if (!message.Processed.IsSet())
                {
                    ResultTasks.TryRemove(message.MessageID, out _);
                    
                    if (message is MethodMessage methodMessage)
                    {
                        var objectException = Wrap.ExecuteSafe(() =>
                        {
                            foreach (var argument in methodMessage.Method.Parameters)
                            {
                                if (argument.Value != null && typeof(IInterObject).IsAssignableFrom(argument.Type.Type))
                                    ((IInterObject)argument.Value).OnCompleted(message.TargetLevel);
                            }
                        });
                        if (objectException != null)
                            Log.EnqueueExceptionSafe(objectException);
                    }

                    if (result != null)
                        message.Result = result;
                    else
                    {
                        if (message.LogExceptions)
                            Log.EnqueueExceptionSafe(exception, null, null, ("Enqueued", "true"));
                        
                        if (exception is SerializableException serializableException)
                            message.Result.Exception = serializableException;
                        else
                            message.Result.Exception = new SerializableException(exception);
                    }
                    message.Processed.Release();
                    Tasks.TryRemove(message.MessageID, out _);
                }
            }
        }

        public static bool IsSet(this SemaphoreSlim semaphore)
        {
            var result = semaphore.Wait(0);
            if (result)
                semaphore.Release();

            return result;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileProcessIdsUsingFileInformation
        {
            public int NumberOfProcessIdsInList;
            public IntPtr ProcessIdList;
        }
        
        [DllImport("ntdll.dll")]
        private static extern uint NtQueryInformationFile(
            SafeHandle FileHandle,
            out IntPtr IoStatusBlock,
            IntPtr FileInformation,
            uint Length,
            int FileInformationClass);
        
        // Unreliable and slow. Takes at least 10ms on an i7-7700 due to the NtQueryInformationFile call.
        // The time scales up depending on the number of running processes on the system, probably because
        // it likely enumerates all processes to find the "locking" process.
        private static int GetClientPID(NamedPipeServerStream namedPipeServer)
        {
            SafePipeHandle handle = namedPipeServer.SafePipeHandle;

            uint bufferLength = 128;

            IntPtr bufferPtr = Marshal.AllocHGlobal((int)bufferLength);
            try
            {
                uint status = NtQueryInformationFile(handle, out _, bufferPtr, bufferLength, 47);
                if (status != 0)
                    throw new Win32Exception((int)status);

                var result = Marshal.PtrToStructure<FileProcessIdsUsingFileInformation>(bufferPtr);
                var processIdsListPtr = IntPtr.Add(bufferPtr, Marshal.OffsetOf<FileProcessIdsUsingFileInformation>("ProcessIdList").ToInt32());

                List<int> processIds = new List<int>();
                for (int i = 0; i < result.NumberOfProcessIdsInList; i++)
                {
                    int processId = Marshal.ReadInt32(processIdsListPtr, i * sizeof(int));
                    processIds.Add(processId);
                }

                return processIds.First();
            }
            finally
            {
                Marshal.FreeHGlobal(bufferPtr);
            }
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetNamedPipeServerProcessId(SafePipeHandle Pipe, out uint ServerProcessId);
        public static void ThrowIfMismatchedServerExePath(NamedPipeClientStream client)
        {
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out uint id))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            
            var currentExe = Win32.ProcessEx.GetCurrentProcessFileLocation();
            if (Win32.ProcessEx.GetProcessFileLocation((int)id) != currentExe)
                throw new SecurityException("Process path mismatch.");
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetNamedPipeClientProcessId(SafePipeHandle Pipe, out uint ClientProcessId);
        public static void ThrowIfMismatchedClientExePath(NamedPipeServerStream server)
        {
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out uint id))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            
            var currentExe = Win32.ProcessEx.GetCurrentProcessFileLocation();
            if (Win32.ProcessEx.GetProcessFileLocation((int)id) != currentExe)
                throw new SecurityException("Process path mismatch.");
        }
        
        private static Task ThrowIfUnauthorizedMessageSender(InterMessage message) => ThrowIfUnauthorizedSender(new VerificationRequest()
        {
            Type = VerificationType.Message,
            TargetLevel = message.CallerLevel,
            CallerLevel = message.TargetLevel,
            IdToVerify = message.MessageID,
            JsonHash = message.JsonHash,
        });

        private static Task ThrowIfUnauthorizedResultSender(MessageResult result) => ThrowIfUnauthorizedSender(new VerificationRequest()
        {
            Type = VerificationType.Result,
            TargetLevel = result.MessageTargetLevel,
            CallerLevel = result.MessageCallerLevel,
            IdToVerify = result.MessageID,
            JsonHash = result.JsonHash,
        });
        
        private static ConcurrentDictionary<InternalLevel, (Task Task, object Lock)> _verifySchedulerQueue = new ConcurrentDictionary<InternalLevel, (Task Task, object Lock)>();
        private static async Task ThrowIfUnauthorizedSender(VerificationRequest request)
        {
            var scheduledAction = (Func<Task, Exception>)(task =>
            {
                return Wrap.ExecuteSafe(() =>
                {
                    NamedPipeClientStream clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{request.TargetLevel}-VerificationReceiver", PipeDirection.InOut, PipeOptions.None);

                    bool retried = false;
                    byte[] json = JsonSerializer.SerializeToUtf8Bytes(request, _serializerOptions);

                    while (true)
                    {
                        try
                        {
                            clientPipe.ConnectAsync(10000).GetAwaiter().GetResult();
                            break;
                        }
                        catch (Exception)
                        {
                            if (retried) throw;

                            retried = true;
                            clientPipe.Dispose();
                            clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{request.TargetLevel}-VerificationReceiver", PipeDirection.InOut, PipeOptions.None);
                        }
                    }

                    ThrowIfMismatchedServerExePath(clientPipe);

                    try
                    {
                        WriteJson(clientPipe, json, 5000, CancellationToken.None, null);

                        byte[] verifiedByte = new byte[] { 0 };
                        using (_ = new SynchronousIoCanceler(5000))
                            clientPipe.Read(verifiedByte, 0, verifiedByte.Length);

                        if (verifiedByte[0] != 1)
                            throw new UnauthorizedAccessException("Verification failed.");
                    }
                    catch (OperationCanceledException)
                    {
                        throw new TimeoutException("Verification request timed out.");
                    }
                    finally
                    {
                        clientPipe.Close();
                    }
                });
            });
            
            var task = _verifySchedulerQueue.GetOrAdd(request.TargetLevel, _ => (Task.CompletedTask, new object()));
            Task<Exception> toBeAwaited;
            lock (task.Lock)
            {
                task.Task = toBeAwaited = task.Task.ContinueWith(scheduledAction);
            }
            var exception = await toBeAwaited;
            if (exception!= null)
                ExceptionDispatchInfo.Capture(exception).Throw();
        }


        private static InternalLevel ThrowIfUnauthorizedMethodAccess(MethodInfo method, TargetLevel targetLevel, InternalLevel callerLevel)
        {
            var attribute = method.GetCustomAttribute<InterprocessMethodAttribute>();
            if (attribute == null)
                throw new UnauthorizedAccessException($"Method '{method.Name}' must have the InterprocessMethod attribute.");

            if (targetLevel == TargetLevel.Auto && (attribute.AuthorizedExecutors.Length > 1 || attribute.AuthorizedExecutors[0] == Level.Any))
                throw new ArgumentException("A specific target level must be specified when multiple InterprocessMethod authorized executors are defined.", nameof(targetLevel));

            if (targetLevel != TargetLevel.Auto && (ApplicationLevel == InternalLevel.Disposable ? (!attribute.AuthorizedExecutors.Contains(targetLevel.ToLevel()) && !attribute.AuthorizedExecutors.Contains(Level.Disposable)) : !attribute.AuthorizedExecutors.Contains(targetLevel.ToLevel())) && !attribute.AuthorizedExecutors.Contains(Level.Any))
                throw new UnauthorizedAccessException($"Access to method '{method.Name}' is denied from target level {targetLevel}.");

            if (!attribute.AuthorizedCallers.Contains(callerLevel.ToLevel()) && !attribute.AuthorizedCallers.Contains(Level.Any))
                throw new UnauthorizedAccessException($"Access to method '{method.Name}' is denied from caller level {targetLevel}.");

            return targetLevel == TargetLevel.Auto ? attribute.AuthorizedExecutors[0].ToInternalLevel() : targetLevel.ToInternalLevel();
        }

        private static void CancelReceiver()
        {
            if (receiverCancel.IsCancellationRequested)
                return;
            
            receiverCancel.Cancel();
        }

        private static void CancelReceiver(Exception exception, bool logException)
        {
            if (receiverCancel.IsCancellationRequested)
                return;
            
            receiverException = exception;
            receiverCancel.Cancel();
            if (logException)
                Log.WriteExceptionSafe(exception);
        }

        private static void CancelSender()
        {
            if (senderCancel.IsCancellationRequested)
                return;
            
            senderCancel.Cancel();
        }

        private static void CancelSender(Exception exception, bool logException)
        {
            if (senderCancel.IsCancellationRequested)
                return;
            
            senderException = exception;
            senderCancel.Cancel();
            if (logException)
                Log.WriteExceptionSafe(exception);
        }


        #region Interfaces

        internal interface IInterObject
        {
            public void BeforeSend(InternalLevel targetLevel);
            public void OnCompleted(InternalLevel targetLevel);
        }

        #endregion

        #endregion
    }

    #region Attributes

    public class InterprocessMethodAttribute : Attribute
    {
        [NotNull] public Level[] AuthorizedExecutors { get; set; }
        [NotNull] public Level[] AuthorizedCallers { get; set; }

        public InterprocessMethodAttribute([NotNull] Level[] authorizedExecutors) : this(authorizedExecutors, new[] { Level.Any }) { }
        public InterprocessMethodAttribute(Level authorizedExecutor) : this(new[] { authorizedExecutor }, Level.Any) { }
        public InterprocessMethodAttribute(Level authorizedExecutor, Level authorizedCaller) : this(new[] { authorizedExecutor }, new[] { authorizedCaller }) { }
        public InterprocessMethodAttribute([NotNull] Level[] authorizedExecutors, Level authorizedCaller) : this(authorizedExecutors, new[] { authorizedCaller }) { }
        public InterprocessMethodAttribute(Level authorizedExecutor, [NotNull] Level[] authorizedCallers) : this(new[] { authorizedExecutor }, authorizedCallers) { }

        public InterprocessMethodAttribute([NotNull] Level[] authorizedExecutors, [NotNull] Level[] authorizedCallers)
        {
            if (authorizedExecutors == null)
                throw new ArgumentNullException(nameof(authorizedExecutors));
            if (authorizedCallers == null)
                throw new ArgumentNullException(nameof(authorizedCallers));

            if (authorizedExecutors.Length == 0)
                throw new ArgumentException("At least one authorized executor level must be specified.");
            if (authorizedCallers.Length == 0)
                throw new ArgumentException("At least one authorized caller level must be specified.");

            AuthorizedExecutors = authorizedExecutors;
            AuthorizedCallers = authorizedCallers;
        }
    }

    #endregion
}