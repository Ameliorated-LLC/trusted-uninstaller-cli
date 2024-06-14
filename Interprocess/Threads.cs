using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using ThreadState = System.Diagnostics.ThreadState;
using Core;
using Core.Miscellaneous;


namespace Interprocess
{
    public partial class InterLink
    {
        #region Input

        private static Thread receiverThread = null;
        private static Thread sendResultThread = null;

        private static Exception receiverException = null;
        private static readonly CancellationTokenSource receiverCancel = new CancellationTokenSource();

        private static readonly BlockingCollection<MessageResult> ResultWriteQueue = new BlockingCollection<MessageResult>();
        private static readonly ConcurrentDictionary<Guid, InterMessage> Tasks = new ConcurrentDictionary<Guid, InterMessage>();

        private static readonly ConcurrentDictionary<Guid, InterProgress> ProgressTasks = new ConcurrentDictionary<Guid, InterProgress>();
        private static readonly ConcurrentDictionary<Guid, InterMessageReporter> MessageReportTasks = new ConcurrentDictionary<Guid, InterMessageReporter>();
        private static readonly ConcurrentDictionary<Guid, MessageResult> ResultTasks = new ConcurrentDictionary<Guid, MessageResult>();
        private static readonly ConcurrentDictionary<Guid, InterCancellationTokenSource> TokenTasks = new ConcurrentDictionary<Guid, InterCancellationTokenSource>();
        private static readonly ConcurrentDictionary<InterCancellationTokenSource, List<SerializableMethod>> ActiveTokens = new ConcurrentDictionary<InterCancellationTokenSource, List<SerializableMethod>>();

        private static void ThrowIfReceiverViolation(InternalLevel level, bool relaunchIfExited)
        {
            receiverCancel.Token.ThrowIfCancellationRequested();
            LevelController.ThrowIfClosedOrExited(level, relaunchIfExited);
            if (_mode == Mode.SendOnly)
                throw new InvalidOperationException($"An attempt was made to send a message to a send-only level '{level}'.");
        }
        
        private static void ReceiverThread(PipeSecurity security)
        {
            var exception = Wrap.ExecuteSafe(() =>
            {
                var serverPipe = new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-Receiver", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
                try
                {
                    while (!receiverCancel.IsCancellationRequested)
                    {
                        try
                        {
                            serverPipe.WaitForConnectionAsync(receiverCancel.Token).GetAwaiter().GetResult();
                        }
                        catch (IOException)
                        {
                            serverPipe.Dispose();
                            serverPipe = new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-Receiver", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
                            continue;
                        }

                        ReadJsonResult jsonResult = null;
                        try
                        {
                            ThrowIfMismatchedClientExePath(serverPipe);
                            try
                            {
                                jsonResult = ReadJson(serverPipe, 2500, CancellationToken.None, true);
                                if (jsonResult.Exception != null || jsonResult.Json == null)
                                    ExceptionDispatchInfo.Capture(jsonResult.Exception ?? new Exception("Failed to read json.")).Throw();
                            }
                            catch (OperationCanceledException)
                            {
                                throw new TimeoutException("Deserialization took too long.");
                            }
                        }
                        catch (Exception e)
                        {
                            Wrap.ExecuteSafe(() => serverPipe.Disconnect());
                            if (jsonResult != null && jsonResult.MessageID.HasValue && jsonResult.Caller.HasValue)
                                ResultWriteQueue.Add(new MessageResult(jsonResult.MessageID.Value, ApplicationLevel, jsonResult.Caller.Value, new SerializableException(e)));
                            Log.EnqueueExceptionSafe(e);
                            continue;
                        }
                        Wrap.ExecuteSafe(() => serverPipe.Disconnect());

                        Task.Run(async () =>
                        {
                            InterMessage message = null;
                            try
                            {
                                message = JsonSerializer.Deserialize<InterMessage>(jsonResult.Json, _serializerOptions);
                                using (MD5 md5 = new MD5CryptoServiceProvider())
                                    message.JsonHash = md5.ComputeHash(jsonResult.Json);

                                if (!(message is ProgressMessage))
                                {
                                    if (!(message is NodeRegistrationMessage))
                                        ThrowIfReceiverViolation(message.CallerLevel, false);
                                    await ThrowIfUnauthorizedMessageSender(message);
                                    ExitIfHostExited();
                                }

                                switch (message)
                                {
                                    case MethodMessage methodMessage:
                                        var exception = Wrap.ExecuteSafe(() =>
                                        {
                                            methodMessage.Method.Method = methodMessage.Method.ParentClass.Type.GetMethod(methodMessage.Method.MethodName, BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Public, null, methodMessage.Method.Parameters.Select(x => x.Type.Type).ToArray(), null)!;
                                            ExecuteMethod(methodMessage);
                                        });
                                        if (exception != null)
                                            ResultWriteQueue.Add(new MessageResult(message.MessageID, ApplicationLevel, message.CallerLevel, new SerializableException(exception)));
                                        return;
                                    case TextMessage textMessage:
                                        var handler = TextReceived;
                                        if (textMessage.Text != null && handler != null)
                                        {
                                            foreach (var invoker in handler.GetInvocationList())
                                            {
                                                _ = SafeTask.Run(() => ((EventHandler<string>)invoker).Invoke(message.CallerLevel, textMessage.Text));
                                            }
                                        }
                                        return;
                                    case ProgressMessage progressMessage:
                                        if (ProgressTasks.TryGetValue(progressMessage.ProgressID, out InterProgress progress))
                                        {
                                            _ = SafeTask.Run(() => progress.OnProgressReceived(progressMessage.Value));
                                        }
                                        return;
                                    case MessageReportMessage reportMessage:
                                        if (MessageReportTasks.TryGetValue(reportMessage.ReporterID, out InterMessageReporter reporter))
                                        {
                                            _ = SafeTask.Run(() => reporter.OnMessageReceived(reportMessage.Value));
                                        }
                                        return;
                                    case NodeRegistrationMessage registrationMessage:
                                        var registrationException = Wrap.ExecuteSafe(() =>
                                        {
                                            var currentExe = Win32.ProcessEx.GetCurrentProcessFileLocation();
                                            if (Win32.ProcessEx.GetProcessFileLocation(registrationMessage.ProcessID) != currentExe)
                                                throw new SecurityException("Process path mismatch.");
                                            
                                            LevelController.Register(registrationMessage.Level, registrationMessage.ProcessID);
                                            LevelController.Open(registrationMessage.Level);

                                            ResultWriteQueue.Add(new MessageResult(message.MessageID, message.TargetLevel, message.CallerLevel, new Serializables.SerializableValue(Process.GetCurrentProcess().Id)));
                                        });
                                        if (registrationException != null)
                                            ResultWriteQueue.Add(new MessageResult(message.MessageID, message.TargetLevel, message.CallerLevel, new SerializableException(registrationException)));
                                        else
                                        {
                                            var registerHandler = NodeRegistered;
                                            if (registerHandler != null)
                                            {
                                                foreach (var invoker in registerHandler.GetInvocationList())
                                                {
                                                    _ = SafeTask.Run(() => ((EventHandler<Level>)invoker).Invoke(null, registrationMessage.Level.ToLevel()), true);
                                                }
                                            }
                                        }
                                        return;
                                    case TokenCancellationMessage cancellationMessage:
                                        var matchingToken = TokenTasks.Values.FirstOrDefault(x => x.SourceLevel == cancellationMessage.SourceLevel && x.ID == cancellationMessage.TokenID) ??
                                                            ActiveTokens.Keys.FirstOrDefault(x => x.SourceLevel == cancellationMessage.SourceLevel && x.ID == cancellationMessage.TokenID);
                                        if (matchingToken == null)
                                            return;

                                        matchingToken.Cancel(message.CallerLevel);
                                        return;
                                    default:
                                        throw new IOException($"Unexpected type '{message.GetType()}' received.");
                                }
                            }
                            catch (Exception e)
                            {
                                if (message != null)
                                    ResultWriteQueue.Add(new MessageResult(message.MessageID, ApplicationLevel, message.CallerLevel, new SerializableException(e)));
                                else if (jsonResult != null && jsonResult.MessageID.HasValue && jsonResult.Caller.HasValue)
                                    ResultWriteQueue.Add(new MessageResult(jsonResult.MessageID.Value, ApplicationLevel, jsonResult.Caller.Value, new SerializableException(e)));
                                throw;
                            }
                        });
                    }
                }
                finally
                {
                    serverPipe.Dispose();
                }
            });

            CancelReceiver(exception ?? new ApplicationException("End of receiver method execution code reached."), true);
        }

        private static void ExecuteMethod(MethodMessage message)
        {
            var method = message.Method.Method;
            if (method.IsGenericMethodDefinition)
            {
                method = method.MakeGenericMethod(message.Method.GenericTypes.Select(x => x.Type).ToArray());
            }

            foreach (var param in message.Method.Parameters)
            {
                if (param.Value is InterCancellationTokenSource icts)
                {
                    lock (ActiveTokens)
                    {
                        var activeToken = ActiveTokens.FirstOrDefault(kvp => kvp.Key.ID == icts.ID && kvp.Key.SourceLevel == icts.SourceLevel);
                        if (activeToken.Key != null)
                        {
                            activeToken.Value.Add(message.Method);
                            param.Value = activeToken.Key;
                        }
                        else
                            ActiveTokens[icts] = new List<SerializableMethod> { message.Method };
                    }
                }
            }

            var result = new MessageResult(message.MessageID, ApplicationLevel, message.CallerLevel, (Serializables.SerializableValue)null);

            try
            {
                // We also do this check here for security purposes
                ThrowIfUnauthorizedMethodAccess(method, ApplicationLevel == InternalLevel.Disposable ? message.CallerLevel.ToTargetLevel() : ApplicationLevel.ToTargetLevel(), message.TargetLevel);

                receiverCancel.Token.ThrowIfCancellationRequested();

                result.Value = new Serializables.SerializableValue(method.ReturnType, method!.Invoke(null, message.Method.Parameters.Select(x => x.Value).ToArray()));

                if (result.Value.Value is Task task)
                {
                    task.GetAwaiter().GetResult();
                    if (task.GetType().IsGenericType)
                    {
                        dynamic taskOfTypeT = task;
                        result.Value = taskOfTypeT.Result == null ? null : new Serializables.SerializableValue(taskOfTypeT.Result.GetType(), taskOfTypeT.Result);
                    }
                }

                receiverCancel.Token.ThrowIfCancellationRequested();
            }
            catch (Exception e)
            {
                result.Value = null;
                if (e is TargetInvocationException invokeException && invokeException.InnerException != null)
                    result.Exception = new SerializableException(receiverException ?? invokeException.InnerException);
                else
                    result.Exception = new SerializableException(receiverException ?? e);
            }

            foreach (var icts in message.Method.Parameters.Select(x => x.Value).OfType<InterCancellationTokenSource>())
            {
                lock (ActiveTokens)
                {
                    if (ActiveTokens.TryGetValue(icts, out List<SerializableMethod> methods))
                    {
                        methods.Remove(message.Method);
                        if (methods.Count == 0)
                        {
                            ActiveTokens.TryRemove(icts, out _);
                            icts.Dispose();
                        }
                    }
                }
            }

            if (receiverCancel.IsCancellationRequested)
                return;

            ResultWriteQueue.Add(result);
        }

        private static Dictionary<InternalLevel, Task> _resultSchedulerQueue = new Dictionary<InternalLevel, Task>();
        private static void SendResultThread()
        {
            var exception = Wrap.ExecuteSafe(() =>
            {
                foreach (var result in ResultWriteQueue.GetConsumingEnumerable(receiverCancel.Token))
                { 
                    var scheduledAction = (Action<Task>)(_ =>
                    {
                        var json = JsonSerializer.SerializeToUtf8Bytes(result, _serializerOptions);
                        if (json.Length > MaxMessageSize)
                        {
                            var exceptionResult = new MessageResult(result.MessageID, result.MessageTargetLevel, result.MessageCallerLevel, new SerializableException(new SerializationException($"Serialized result data exceeded the maximum message size ({json.Length / 1024}KB > {MaxMessageSize / 1024}KB).")));
                            json = JsonSerializer.SerializeToUtf8Bytes(exceptionResult, _serializerOptions);
                        }

                        byte[] jsonHash;
                        using (MD5 md5 = new MD5CryptoServiceProvider())
                            jsonHash = md5.ComputeHash(json);

                        var clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{result.MessageCallerLevel}-ResultReceiver", PipeDirection.Out, PipeOptions.None);
                        try
                        {
                            bool retried = false;
                            while (true)
                            {
                                try
                                {
                                    clientPipe.ConnectAsync(10000).GetAwaiter().GetResult();
                                    break;
                                }
                                catch (Exception e)
                                {
                                    if (retried)
                                        throw;

                                    Log.EnqueueExceptionSafe(e, null, null, ("Caller", result.MessageCallerLevel), ("Result", result.Value?.Value));

                                    retried = true;

                                    clientPipe.Dispose();
                                    Thread.Sleep(100);
                                    clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{result.MessageCallerLevel}-ResultReceiver", PipeDirection.Out, PipeOptions.None);
                                }
                            }
                            
                            ThrowIfMismatchedServerExePath(clientPipe);

                            ResultTasks.AddOrUpdate(result.MessageID, _ => result, (_, old) =>
                            {
                                Log.EnqueueSafe(LogType.Warning, "Overrode matched result MessageID", new SerializableTrace());
                                return result;
                            });
                            result.PendingVerification = true;
                            result.JsonHash = jsonHash;
                            
                            WriteJson(clientPipe, json, 5000, CancellationToken.None, null);
                        }
                        finally
                        {
                            clientPipe.Dispose();
                        }
                    });
                    
                    if (!_resultSchedulerQueue.TryGetValue(result.MessageCallerLevel, out var task))
                        _resultSchedulerQueue[result.MessageCallerLevel] = (task = Task.CompletedTask);

                    _resultSchedulerQueue[result.MessageCallerLevel] = task.ContinueWith(scheduledAction);
                }
            }, true);

            CancelReceiver(exception ?? new ApplicationException("End of receiver method execution code reached."), true);
        }

        #endregion


        #region Output

        private static Thread senderThread = null;
        private static Thread receiveResultThread = null;

        private static Exception senderException = null;
        private static readonly CancellationTokenSource senderCancel = new CancellationTokenSource();
        private static readonly BlockingCollection<InterMessage> MessageWriteQueue = new BlockingCollection<InterMessage>();

        private static void ThrowIfSenderViolation(InternalLevel level, bool relaunchIfExited)
        {
            senderCancel.Token.ThrowIfCancellationRequested();
            LevelController.ThrowIfClosedOrExited(level, relaunchIfExited);
            if (_mode == Mode.ReceiveOnly)
                throw new InvalidOperationException($"An attempt was made to send a message from a receive-only level '{level}'.");
        }

        private static Dictionary<InternalLevel, Task> _messageSchedulerQueue = new Dictionary<InternalLevel, Task>();
        private static void SenderThread()
        {
            var exception = Wrap.ExecuteSafe(() =>
            {
                foreach (var message in MessageWriteQueue.GetConsumingEnumerable(senderCancel.Token))
                {
                    var scheduledAction = (Action<Task>)(_ =>
                    {
                        try
                        {
                            if (!(message is ProgressMessage))
                            {
                                message.MessageID = Guid.NewGuid();
                                Tasks.AddOrUpdate(message.MessageID, _ => message, (_, old) =>
                                {
                                    Log.EnqueueSafe(LogType.Warning, "Overrode matched message MessageID", new SerializableTrace());
                                    return message;
                                });
                            }

                            var json = JsonSerializer.SerializeToUtf8Bytes(message, _serializerOptions);
                            if (json.Length > MaxMessageSize)
                            {
                                SetMessageResult(message, null, new SerializationException($"Serialized message data exceeded the maximum message size ({json.Length / 1024}KB > {MaxMessageSize / 1024}KB)."));
                                return;
                            }

                            using (MD5 md5 = new MD5CryptoServiceProvider())
                                message.JsonHash = md5.ComputeHash(json);

                            var clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{message.TargetLevel}-Receiver", PipeDirection.Out, PipeOptions.None);
                            try
                            {
                                bool retried = false;
                                while (true)
                                {
                                    if (!message.Enqueued && message.TargetLevel != InternalLevel.Disposable)
                                        ThrowIfSenderViolation(message.TargetLevel, true);
                                    try
                                    {
                                        clientPipe.ConnectAsync(!message.Enqueued ? 10000 : Math.Min(Math.Max(100, message.EnqueueTimeout), 10000)).GetAwaiter().GetResult();
                                        break;
                                    }
                                    catch (Exception e)
                                    {
                                        if (message.Enqueued)
                                        {
                                            message.EnqueueTimeout -= 10000;
                                            if (message.EnqueueTimeout < 100)
                                            {
                                                SetMessageResult(message, null, new TimeoutException(e.Message));
                                                return;
                                            }
                                            Task.Delay(Math.Min(Math.Max(100, message.EnqueueTimeout), 1000)).ContinueWith(_ => MessageWriteQueue.Add(message));
                                            return;
                                        }

                                        if (retried)
                                            throw;

                                        clientPipe.Dispose();

                                        if (message.TargetLevel != InternalLevel.Disposable)
                                            ThrowIfSenderViolation(message.TargetLevel, true);
                                        Log.EnqueueExceptionSafe(e, null, null, ("Target", message.TargetLevel));

                                        retried = true;

                                        Thread.Sleep(100);
                                        clientPipe = new NamedPipeClientStream(".", $"{PipePrefix}-{message.TargetLevel}-Receiver", PipeDirection.Out, PipeOptions.None);
                                    }
                                }
                                ThrowIfMismatchedServerExePath(clientPipe);

                                message.PendingVerification = true;

                                try
                                {
                                    WriteJson(clientPipe, json, 10000, message.TargetLevel == InternalLevel.Disposable ? CancellationToken.None : LevelController.GetCloseToken(message.TargetLevel), message);
                                }
                                catch (OperationCanceledException)
                                {
                                    if (message.TargetLevel != InternalLevel.Disposable)
                                        LevelController.GetCloseToken(message.TargetLevel).ThrowIfCancellationRequested();
                                    throw new TimeoutException("Took too long to send a message.");
                                }

                                message.Sent = true;

                                if (message is ProgressMessage)
                                    SetMessageResult(message, MessageResult.Empty, null);
                            }
                            finally
                            {
                                clientPipe.Dispose();
                            }
                        }
                        catch (Exception ex)
                        {
                            if (message is MethodMessage methodMessage)
                                Log.EnqueueExceptionSafe(ex, null, null, ("Target", message.TargetLevel), ("Method", methodMessage.Method.MethodName));
                            else
                                Log.EnqueueExceptionSafe(ex, null, null, ("Target", message.TargetLevel), ("MessageType", message.GetType().Name.Split('.').Last()));
                            SetMessageResult(message, null, senderException ?? ex);
                        }
                    });

                    if (!_messageSchedulerQueue.TryGetValue(message.TargetLevel, out var task))
                        _messageSchedulerQueue[message.TargetLevel] = (task = Task.CompletedTask);

                    _messageSchedulerQueue[message.TargetLevel] = task.ContinueWith(scheduledAction);
                }
            });

            if (!senderCancel.IsCancellationRequested)
            {
                foreach (var message in Tasks.Values)
                    SetMessageResult(message, null, senderException ?? exception ?? new ApplicationException("Unexpected SendMethodThread loop exit."));

                CancelSender(senderException ??= exception ?? new ApplicationException("End of receiver method execution code reached."), true);
            }
        }


        private static void ReceiveResultThread(PipeSecurity security)
        {
            var exception = Wrap.ExecuteSafe(() =>
            {
                var serverPipe = new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-ResultReceiver", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
                try
                {
                    while (!senderCancel.IsCancellationRequested)
                    {
                        try
                        {
                            serverPipe.WaitForConnectionAsync(senderCancel.Token).GetAwaiter().GetResult();
                        }
                        catch (IOException)
                        {
                            serverPipe.Dispose();
                            serverPipe = new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-ResultReceiver", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
                            continue;
                        }

                        byte[] json;
                        try
                        {
                            ThrowIfMismatchedClientExePath(serverPipe);
                            
                            try
                            {
                                json = ReadJson(serverPipe, 2500, CancellationToken.None, false).Json!;
                            }
                            catch (OperationCanceledException)
                            {
                                throw new TimeoutException("Deserialization took too long.");
                            }

                        }
                        catch (Exception e)
                        {
                            Wrap.ExecuteSafe(() => serverPipe.Disconnect());
                            Log.EnqueueExceptionSafe(e);
                            continue;
                        }
                        Wrap.ExecuteSafe(() => serverPipe.Disconnect());

                        SafeTask.Run(async () =>
                        {
                            var result = JsonSerializer.Deserialize<MessageResult>(json, _serializerOptions);
                            if (result.MessageTargetLevel != InternalLevel.Disposable)
                                ThrowIfSenderViolation(result.MessageTargetLevel, false);

                            using (MD5 md5 = new MD5CryptoServiceProvider())
                                result.JsonHash = md5.ComputeHash(json);
                            await ThrowIfUnauthorizedResultSender(result);
                            
                            ExitIfHostExited();

                            if (result.MessageID == Guid.Empty)
                            {
                                Log.EnqueueSafe(LogType.Warning, "Invalid empty result Guid.", null);
                                return;
                            }

                            Tasks.TryRemove(result.MessageID, out InterMessage message);
                            if (message != null)
                                SetMessageResult(message, result, null);
                        }, true);
                    }
                }
                finally
                {
                    serverPipe.Dispose();
                }
            });

            if (!senderCancel.IsCancellationRequested)
            {
                foreach (var message in Tasks.Values)
                    SetMessageResult(message, null, senderException ?? exception!);

                CancelSender(exception ?? new ApplicationException("End of receiver method execution code reached."), true);
            }
        }

        #endregion


        #region Verification

        private static Thread verificationThread;

        private static void VerificationThread(PipeSecurity security)
        {
            var serverPipe = Wrap.ExecuteSafe(() => new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-VerificationReceiver", PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security), true).Value;
            try
            {
                var exception = Wrap.ExecuteSafe(() =>
                {
                    if (serverPipe == null)
                        throw new ApplicationException("Could not initialize verification receiver.");

                    using var compositeToken = CreateCompositeCancellationTokenSource(senderCancel.Token, receiverCancel.Token);

                    while (!compositeToken.IsCancellationRequested)
                    {
                        try
                        {
                            serverPipe.WaitForConnectionAsync(compositeToken.Token).GetAwaiter().GetResult();
                        }
                        catch (IOException)
                        {
                            serverPipe.Dispose();
                            serverPipe = new NamedPipeServerStream($"{PipePrefix}-{ApplicationLevel}-VerificationReceiver", PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 0, 0, security);
                            continue;
                        }

                        byte[] verified = new byte[1];
                        try
                        {
                            ThrowIfMismatchedClientExePath(serverPipe);
                            
                            
                            byte[] json;
                            try
                            {
                                json = ReadJson(serverPipe, 5000, CancellationToken.None, false).Json;
                            }
                            catch (OperationCanceledException)
                            {
                                throw new TimeoutException("Deserialization took too long.");
                            }

                            var request = JsonSerializer.Deserialize<VerificationRequest>(json, _serializerOptions);
                            
                            switch (request.Type)
                            {
                                case VerificationType.Message:
                                    senderCancel.Token.ThrowIfCancellationRequested();
                                    verified[0] = VerifyMessage(request) ? (byte)1 : (byte)0;
                                    break;
                                case VerificationType.Result:
                                    receiverCancel.Token.ThrowIfCancellationRequested();
                                    verified[0] = VerifyResult(request) ? (byte)1 : (byte)0;
                                    break;
                                default:
                                    Wrap.ExecuteSafe(() => serverPipe.Disconnect());
                                    Log.EnqueueSafe(LogType.Warning, "Unkown verification request type received.", null, null, ("Request Type", request.Type), ("Request Caller", request.CallerLevel));
                                    continue;
                            }

                            try
                            {
                                using (_ = new SynchronousIoCanceler(5000))
                                    serverPipe.Write(verified, 0, verified.Length);
                            }
                            catch (OperationCanceledException)
                            {
                                throw new TimeoutException("Verification write took too long.");
                            }

                            if (ApplicationLevel == InternalLevel.Disposable && verified[0] == 1 && request.Type == VerificationType.Result)
                                Environment.Exit(0);
                        }
                        catch (Exception e)
                        {
                            Wrap.ExecuteSafe(() => serverPipe.Disconnect());
                            Log.EnqueueExceptionSafe(e);
                            continue;
                        }
                        Wrap.ExecuteSafe(() => serverPipe.Disconnect());
                    }
                });

                if (ApplicationLevel == InternalLevel.Disposable)
                {
                    Log.WriteExceptionSafe(exception);
                    Environment.Exit(57);
                }

                Log.EnqueueExceptionSafe(exception);
                CloseConnection(false);
            }
            finally
            {
                serverPipe?.Dispose();
            }
        }

        public static CancellationTokenSource CreateCompositeCancellationTokenSource(CancellationToken token1, CancellationToken token2)
        {
            var linkedTokenSource = new CancellationTokenSource();

            token1.Register(() => 
            {
                if (token1.IsCancellationRequested && token2.IsCancellationRequested) 
                    linkedTokenSource.Cancel();
            });

            token2.Register(() => 
            {
                if (token1.IsCancellationRequested && token2.IsCancellationRequested) 
                    linkedTokenSource.Cancel();
            });

            return linkedTokenSource;
        }

        private static bool VerifyMessage(VerificationRequest request)
        {
            var verifiedMessage = Tasks.Values.FirstOrDefault(message =>
            {
                var verified =
                    message.PendingVerification &&
                    message.MessageID == request.IdToVerify &&
                    message.TargetLevel == request.CallerLevel &&
                    message.CallerLevel == request.TargetLevel &&
                    message.JsonHash.SequenceEqual(request.JsonHash);

                if (verified)
                    message.PendingVerification = false;

                return verified;
            });
            if (verifiedMessage != null && !(verifiedMessage is MethodMessage || verifiedMessage is NodeRegistrationMessage))
                SetMessageResult(verifiedMessage, MessageResult.Empty, null);

            return verifiedMessage != null;
        }

        private static bool VerifyResult(VerificationRequest request)
        {
            return ResultTasks.Values.Any(result =>
            {
                bool verified =
                    result.PendingVerification &&
                    result.MessageID == request.IdToVerify &&
                    result.MessageTargetLevel == request.TargetLevel &&
                    result.MessageCallerLevel == request.CallerLevel &&
                    result.JsonHash.SequenceEqual(request.JsonHash);

                if (verified)
                    result.PendingVerification = false;

                return verified;
            });
        }

        #endregion
    }
}