using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Serialization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using Core.Miscellaneous;
using JetBrains.Annotations;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;
using ThreadState = System.Threading.ThreadState;

namespace Core
{
    public enum LogType
    {
        Info,
        Warning,
        Error,
        Critical,
        Debug,
    }

    #region Serializables

    [Serializable]
    public class SerializableTrace : ICloneable
    {
        public TraceFrame[] Frames { get; set; }
        public string Source { get; set; }
        public SerializableThread Thread { get; set; }

        public object Clone()
        {
            TraceFrame[] cloneFrames = new TraceFrame[Frames.Length];
            Array.Copy(Frames, cloneFrames, Frames.Length);

            return new SerializableTrace()
            {
                Frames = cloneFrames,
                Source = Source,
                Thread = Thread
            };
        }

        [JsonConstructor]
        public SerializableTrace(SerializableThread thread) => Thread = thread;

        public SerializableTrace(string source = null, int skipFrames = 0, int takeFrames = Int32.MaxValue) : this(null, source, skipFrames + 1, takeFrames) { }

        public SerializableTrace(Exception exception, string source = null, int skipFrames = 0, int takeFrames = Int32.MaxValue)
        {
            Source = source ?? Log.CurrentSource;
            Thread = new SerializableThread(System.Threading.Thread.CurrentThread);

            var stackTrace = exception == null ? new StackTrace(1 + skipFrames, true) : new StackTrace(exception, skipFrames, true);
            if (exception != null && stackTrace.FrameCount == 0)
            {
                stackTrace = new StackTrace(1 + skipFrames, true);
                takeFrames = Math.Min(takeFrames, 5);
            }

            var trace = new EnhancedStackTrace(stackTrace);
            var frames = (EnhancedStackFrame[])trace.GetFrames();

            var frameList = new List<TraceFrame>();

            int taken = 0;
            foreach (var frame in frames)
            {
                if (taken >= takeFrames)
                    break;

                var methodName = frame.MethodInfo.Append(new StringBuilder(), false).ToString();
                frameList.Add(new TraceFrame()
                {
                    MethodName = methodName,
                    FileName = Path.GetFileName(frame.GetFileName()),
                    FileLineNumber = frame.GetFileLineNumber(),
                    FileColumnNumber = frame.GetFileColumnNumber(),
                });

                taken++;

                if (methodName.Contains("App.OnStartup(StartupEventArgs e)"))
                    break;
            }

            Frames = frameList.ToArray();
        }

        internal void Append(SerializableTrace append)
        {
            var frames = new TraceFrame[Frames.Length + append.Frames.Length + 1];

            int i;
            for (i = 0; i < append.Frames.Length; i++)
            {
                frames[i].MethodName = append.Frames[i].MethodName;
                frames[i].FileName = Path.GetFileName(append.Frames[i].FileName);
                frames[i].FileLineNumber = append.Frames[i].FileLineNumber;
                frames[i].FileColumnNumber = append.Frames[i].FileColumnNumber;
            }
            frames[i].MethodName = $"[{append.Source}]";
            i++;
            for (int j = 0; j < Frames.Length; j++, i++)
            {
                frames[i].MethodName = Frames[j].MethodName;
                frames[i].FileName = Path.GetFileName(Frames[j].FileName);
                frames[i].FileLineNumber = Frames[j].FileLineNumber;
                frames[i].FileColumnNumber = Frames[j].FileColumnNumber;
            }

            Frames = frames;
        }

        internal void Prepend(SerializableTrace prepend)
        {
            var frames = new TraceFrame[Frames.Length + prepend.Frames.Length + 1];

            int i;
            for (i = 0; i < Frames.Length; i++)
            {
                frames[i].MethodName = Frames[i].MethodName;
                frames[i].FileName = Path.GetFileName(Frames[i].FileName);
                frames[i].FileLineNumber = Frames[i].FileLineNumber;
                frames[i].FileColumnNumber = Frames[i].FileColumnNumber;
            }
            frames[i].MethodName = $"[{Source}]";
            i++;
            for (int j = 0; j < prepend.Frames.Length; j++, i++)
            {
                frames[i].MethodName = prepend.Frames[j].MethodName;
                frames[i].FileName = Path.GetFileName(prepend.Frames[j].FileName);
                frames[i].FileLineNumber = prepend.Frames[j].FileLineNumber;
                frames[i].FileColumnNumber = prepend.Frames[j].FileColumnNumber;
            }

            Frames = frames;
            Source = prepend.Source;
        }

        private string _stringValue { get; set; } = null;

        public override string ToString() => ToString(null);
        public string ToString([CanBeNull] string source)
        {
            if (_stringValue != null)
                return _stringValue;

            var threadString = Wrap.ExecuteSafe(() =>
            {
                return ((Thread.ApartmentState == ApartmentState.STA || Thread.ManagedThreadId == 1) &&
                        !Thread.IsBackground && !Thread.IsThreadPoolThread) ? "" :
                    Thread.ThreadState != System.Threading.ThreadState.Running && Thread.IsAlive ? $" ({Thread.ThreadState.ToString()} TID {Thread.ManagedThreadId})" : $" (TID {Thread.ManagedThreadId})";
            }).Value;

            var traceBuilder = new StringBuilder($"[{source ?? Source ?? (Log.CurrentSource + threadString)}]");
            var traceString = Wrap.ExecuteSafe(() =>
            {
                foreach (var frame in Frames.Reverse())
                {
                    var name = Log.RemoveParameterTypes(frame.MethodName);
                    if (String.IsNullOrWhiteSpace(name))
                        continue;

                    string fileName = Path.GetFileName(frame.FileName);
                    int lineNumber = frame.FileLineNumber;
                    traceBuilder.Append((traceBuilder.Length == 0 ? "" : " >" + Environment.NewLine) + name + (String.IsNullOrWhiteSpace(fileName) ? "" : " in " + fileName) + (lineNumber == 0 ? "" : ":" + lineNumber));
                }

                var traceString = traceBuilder.ToString();
                if (Regex.IsMatch(traceString, @"Wrap\.Execute[a-zA-Z]*Safe"))
                {
                    // Remove useless Polly execute lines
                    return Regex.Replace(traceString, @".*Polly\.ResiliencePipeline\.Execute.*\n", "");
                }

                return traceString;
            }).Value;

            _stringValue = traceString ?? traceBuilder.ToString();
            return _stringValue;
        }

        [Serializable]
        public struct TraceFrame
        {
            public string MethodName { get; set; }
            [CanBeNull] public string FileName { get; set; }
            public int FileLineNumber { get; set; }
            public int FileColumnNumber { get; set; }
        }

        [Serializable]
        public struct SerializableThread
        {
            public ApartmentState ApartmentState { get; set; }
            public int ManagedThreadId { get; set; }
            public bool IsBackground { get; set; }
            public bool IsThreadPoolThread { get; set; }
            public ThreadState ThreadState { get; set; }
            public bool IsAlive { get; set; }

            public SerializableThread(Thread thread)
            {
                ApartmentState = thread.GetApartmentState();
                ManagedThreadId = thread.ManagedThreadId;
                IsBackground = thread.IsBackground;
                IsThreadPoolThread = thread.IsThreadPoolThread;
                ThreadState = thread.ThreadState;
                IsAlive = thread.IsAlive;
            }
        }
    }

    [Serializable]
    public class SerializableException : Exception, IJsonOnDeserialized
    {
        public SerializableTrace Trace { get; set; }
        public string OriginalTraceString { get; set; }
        public Serializables.SerializableType OriginalType { get; set; }
        public new string Message { get; set; }

        [CanBeNull] public new SerializableException InnerException { get; set; } = null;
        [CanBeNull] public SerializableException[] AggregateInnerExceptions { get; set; } = null;

        [JsonIgnore] public bool WasDeserialized { get; set; } = false;

        [JsonConstructor]
        public SerializableException(Serializables.SerializableType originalType) => OriginalType = originalType;

        public void OnDeserialized()
        {
            SetMessage(this, Message);
            SetStackTrace(this, OriginalTraceString);
            typeof(Exception).GetField("_className", BindingFlags.NonPublic | BindingFlags.Instance)?.SetValue(this, OriginalType?.Type?.ToString() ?? "SerializableException");
            WasDeserialized = true;
        }

        public SerializableException([NotNull] Exception exception, string message = null) : this(exception, message, 0) { }

        private SerializableException([NotNull] Exception exception, string message = null, int skipFrames = 0) : base(message == null ? exception.Message : message.TrimEnd('.') + ": " + exception.Message)
        {
            Message = message == null ? exception.Message : message.TrimEnd('.') + ": " + exception.Message;
            
            if (exception is SerializableException serializableException)
            {
                this.Trace = (SerializableTrace)serializableException.Trace.Clone();
                this.OriginalTraceString = serializableException.OriginalTraceString;
                this.OriginalType = serializableException.OriginalType;
                this.Message = message == null ? serializableException.Message : message.TrimEnd('.') + ": " + serializableException.Message;
                this.InnerException = serializableException.InnerException;
                this.AggregateInnerExceptions = serializableException.AggregateInnerExceptions;
                this.Trace.Append(new SerializableTrace("Duplicated at", 1, 1));

                OnDeserialized();
                WasDeserialized = false;

                return;
            }

            if (exception is Win32Exception win32Exception)
            {
                var rawMessage = new Win32Exception(win32Exception.NativeErrorCode).Message;
                if (rawMessage != win32Exception.Message)
                {
                    // Message has been set manually by the Win32Exception constructor, so append the valuable win32 error message
                    Message = Message.TrimEnd('.') + ": " + rawMessage;
                }
            }

            if (exception.InnerException != null)
                InnerException = new SerializableException(exception.InnerException, null, skipFrames + 1);
            if (exception is AggregateException aggregateException)
                AggregateInnerExceptions = aggregateException.InnerExceptions.Select(x => new SerializableException(x, null, skipFrames + 1)).ToArray();

            Trace = new SerializableTrace(exception, null, skipFrames);
            OriginalType = new Serializables.SerializableType(exception.GetType());
            OriginalTraceString = exception.StackTrace;

            OnDeserialized();
            WasDeserialized = false;
        }

        private void SetStackTrace(Exception exception, string stackTrace)
        {
            var stackTraceField = typeof(Exception).GetField("_stackTraceString", BindingFlags.NonPublic | BindingFlags.Instance);
            if (stackTraceField != null && stackTrace != null)
                stackTraceField.SetValue(exception, null);
            var remoteStackTraceField = typeof(Exception).GetField("_remoteStackTraceString", BindingFlags.NonPublic | BindingFlags.Instance);
            if (remoteStackTraceField != null && stackTrace != null)
                remoteStackTraceField.SetValue(exception, stackTrace + Environment.NewLine);

            var stackTraceObjectField = typeof(Exception).GetField("_stackTrace", BindingFlags.NonPublic | BindingFlags.Instance);
            if (stackTraceObjectField != null && stackTrace != null)
                stackTraceObjectField.SetValue(exception, null);
        }

        private void SetMessage(Exception exception, string message)
        {
            var messageField = typeof(Exception).GetField("_message", BindingFlags.NonPublic | BindingFlags.Instance);
            if (messageField != null && message != null)
            {
                messageField.SetValue(exception, message);
            }
        }
    }

    #endregion

    public static class Log
    {
        public const string GlobalLog = @"%PROGRAMDATA%\AME\Logs\Log.yml";
        public static string CurrentSource { get; set; } = "Unknown";
        public static ILogMetadata MetadataSource = new LogMetadata();
        public static string LogFileOverride { get; set; } = null;

        private static Thread _logThread = null;
        private static CancellationTokenSource _logThreadCancel = null;
        private static readonly BlockingCollection<LogMessage> Queue = new BlockingCollection<LogMessage>();

        #region Public write methods

        public class LogOptions
        {
            public static LogOptions Default { get; } = new LogOptions()
            {
                LogFile = GlobalLog,
            };

            public LogOptions() { }
            public LogOptions(string logFile) => LogFile = logFile;
            public LogOptions(Output.OutputWriter writer) => OutputWriter = writer;
            public LogOptions(string logFile, Output.OutputWriter writer) => (OutputWriter, LogFile) = (writer, logFile);

            public string LogFile { get; set; }
            public Output.OutputWriter OutputWriter { get; set; }
            public string SourceOverride { get; set; } = null;
        }
        
        public static void EnqueueSafe(LogType type, [NotNull] string message, [CanBeNull] SerializableTrace trace, params (string Name, object Value)[] data) => EnqueueSafe(type, message, trace,null, data);
        public static void EnqueueSafe(LogType type, [NotNull] string message, [CanBeNull] SerializableTrace trace, [CanBeNull] LogOptions options = null, params (string Name, object Value)[] data)
        {
#if !DEBUG
            if (type == LogType.Debug)
                return;
#endif
            if (options?.OutputWriter != null)
            {
                WriteSafe(type, message, trace, options, data);
                return;
            }
            
            CheckLogThread();

            Queue.Add(new LogMessage { FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Type = type, Message = message, Trace = trace, Time = DateTime.UtcNow, SourceOverride = options?.SourceOverride, Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null") });
        }

        public static void EnqueueExceptionSafe(Exception exception, params (string Name, object Value)[] data) => EnqueueExceptionSafe(exception, null, null,null, data);
        public static void EnqueueExceptionSafe(Exception exception, [CanBeNull] string message, params (string Name, object Value)[] data) => EnqueueExceptionSafe(exception, message, null,null, data);
        public static void EnqueueExceptionSafe(Exception exception, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => EnqueueExceptionSafe(exception, null, options, source, data);
        public static void EnqueueExceptionSafe(Exception exception, [CanBeNull] string message, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => EnqueueExceptionSafe(LogType.Error, exception, message, options, source, data);
        public static void EnqueueExceptionSafe(LogType type, Exception exception, params (string Name, object Value)[] data) => EnqueueExceptionSafe(type, exception, null, null,null, data);
        public static void EnqueueExceptionSafe(LogType type, Exception exception, [CanBeNull] string message, params (string Name, object Value)[] data) => EnqueueExceptionSafe(type, exception, message, null,null, data);
        public static void EnqueueExceptionSafe(LogType type, Exception exception, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => EnqueueExceptionSafe(type, exception, null, options, source, data);
        public static void EnqueueExceptionSafe(LogType type, Exception exception, [CanBeNull] string message, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data)
        {
            if (exception == null && message == null)
                return;

            if (exception == null)
            {
                EnqueueSafe(LogType.Error, $"[Unknown] " + message, new SerializableTrace(source, 1), options, data);
                return;
            }

            if (options?.OutputWriter != null)
            {
                WriteExceptionSafe(type, exception, message, options, source, data);
                return;
            }
            
            string exceptionMessage = exception.GetRealMessage();
            if (message != null)
                exceptionMessage = message.TrimEnd('.') + ": " + exceptionMessage;
            
            var logMessage = new LogMessage() { Type = type, Message = $"[{exception.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + exceptionMessage, Trace = new SerializableTrace(exception, source ?? options?.SourceOverride, 1), Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null"), FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Time = DateTime.UtcNow, SourceOverride = source ?? options?.SourceOverride };

            if (exception is SerializableException serializableException)
            {
                logMessage = new LogMessage() { Type = type, Message = $"[{serializableException.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + (exceptionMessage), Trace = serializableException.Trace, Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null"), FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Time = DateTime.UtcNow, SourceOverride = source ?? options?.SourceOverride };

                if (serializableException.AggregateInnerExceptions != null)
                    logMessage.Nested = serializableException.AggregateInnerExceptions.Select(x => new LogMessage() { Type = null, Time = null, Trace = x.Trace, Message = $"[(Aggregate) {x.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + x.GetRealMessage() }).ToArray();
                if (serializableException.InnerException != null)
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = serializableException.InnerException.Trace, Message = $"[(Inner) {serializableException.InnerException.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + serializableException.InnerException.GetRealMessage() };
                    logMessage.Nested = logMessage.Nested == null ? new[] { innerMessage } : logMessage.Nested.Concat(new[] { innerMessage }).ToArray();
                }
            }
            else if (exception is AggregateException aggregate)
            {
                logMessage.Nested = aggregate.InnerExceptions.Select(x => new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(x, null, 1), Message = $"[(Aggregate) {x.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + x.GetRealMessage()}).ToArray();

                if (aggregate.InnerException != null && !aggregate.InnerExceptions.Any(x => x == aggregate.InnerException))
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(aggregate.InnerException, null, 1), Message = $"[(Inner) {aggregate.InnerException.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + aggregate.InnerException.GetRealMessage() };
                    logMessage.Nested = logMessage.Nested.Concat(new[] { innerMessage }).ToArray();
                }
            }
            else
            {
                if (exception.InnerException != null)
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(exception.InnerException, null, 1), Message = $"[(Inner) {exception.InnerException.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + exception.InnerException.GetRealMessage() };
                    logMessage.Nested = new[] { innerMessage };
                }
            }

            CheckLogThread();
            Queue.Add(logMessage);
        }

        public static void WriteSafe(LogType type, [NotNull] string message, [CanBeNull] SerializableTrace trace, params (string Name, object Value)[] data) => WriteSafe(type, message, trace,null, data);
        public static void WriteSafe(LogType type, [NotNull] string message, [CanBeNull] SerializableTrace trace, [CanBeNull] LogOptions options = null, params (string Name, object Value)[] data)
        {
#if !DEBUG
            if (type == LogType.Debug)
                return;
#endif

            var exception = Wrap.ExecuteSafe(() =>
            {
                var logMessage = new LogMessage { FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Type = type, Message = message, Trace = trace, Time = DateTime.UtcNow, SourceOverride = options?.SourceOverride, Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null") };

                Write(logMessage, options?.OutputWriter);
            });
            if (exception != null)
                Log.EnqueueExceptionSafe(exception, source: "Logger");
        }

        public static void WriteExceptionSafe(Exception exception, params (string Name, object Value)[] data) => WriteExceptionSafe(exception, null, null,null, data);
        public static void WriteExceptionSafe(Exception exception, [CanBeNull] string message, params (string Name, object Value)[] data) => WriteExceptionSafe(exception, message, null,null, data);
        public static void WriteExceptionSafe(Exception exception, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => WriteExceptionSafe(exception, null, options, source, data);
        public static void WriteExceptionSafe(Exception exception, [CanBeNull] string message, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => WriteExceptionSafe(LogType.Error, exception, message, options, source, data);
        public static void WriteExceptionSafe(LogType type, Exception exception, params (string Name, object Value)[] data) => WriteExceptionSafe(type, exception, null, null,null, data);
        public static void WriteExceptionSafe(LogType type, Exception exception, [CanBeNull] string message, params (string Name, object Value)[] data) => WriteExceptionSafe(type, exception, message, null,null, data);
        public static void WriteExceptionSafe(LogType type, Exception exception, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data) => WriteExceptionSafe(type, exception, null, options, source, data);
        public static void WriteExceptionSafe(LogType type, Exception exception, [CanBeNull] string message, [CanBeNull] LogOptions options = null, string source = null, params (string Name, object Value)[] data)
        {
            if (exception == null && message == null)
                return;

            if (exception == null)
            {
                WriteSafe(LogType.Error, $"[Unknown] " + message, new SerializableTrace(source, 1), options, data);
                return;
            }

            string exceptionMessage = exception.GetRealMessage();
            if (message != null)
                exceptionMessage = message.ToString().TrimEnd('.') + ": " + exceptionMessage;
            
            var logMessage = new LogMessage() { Type = type, Message = $"[{exception.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + exceptionMessage, Trace = new SerializableTrace(exception, source ?? options?.SourceOverride, 1), Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null"), FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Time = DateTime.UtcNow, SourceOverride = source ?? options?.SourceOverride };

            if (exception is SerializableException serializableException)
            {
                logMessage = new LogMessage() { Type = type, Message = $"[{serializableException.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + exceptionMessage, Trace = serializableException.Trace, Data = (data?.Length ?? 0) == 0 ? null : data.ToDictionary(tuple => tuple.Name, tuple => tuple.Value?.ToString() ?? "null"), FilePath = options?.LogFile ?? LogOptions.Default.LogFile, Time = DateTime.UtcNow, SourceOverride = source ?? options?.SourceOverride };

                if (serializableException.AggregateInnerExceptions != null)
                    logMessage.Nested = serializableException.AggregateInnerExceptions.Select(x => new LogMessage() { Type = null, Time = null, Trace = x.Trace, Message = $"[(Aggregate) {x.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + x.GetRealMessage() }).ToArray();
                if (serializableException.InnerException != null)
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = serializableException.InnerException.Trace, Message = $"[(Inner) {serializableException.InnerException.OriginalType.Type.ToString().Split(new[] { '.', '+' }).Last()}] " + serializableException.InnerException.GetRealMessage() };
                    logMessage.Nested = logMessage.Nested == null ? new[] { innerMessage } : logMessage.Nested.Concat(new[] { innerMessage }).ToArray();
                }
            }
            else if (exception is AggregateException aggregate)
            {
                logMessage.Nested = aggregate.InnerExceptions.Select(x => new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(x, null, 1), Message = $"[(Aggregate) {x.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + x.GetRealMessage()}).ToArray();

                if (aggregate.InnerException != null && !aggregate.InnerExceptions.Any(x => x == aggregate.InnerException))
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(aggregate.InnerException, null, 1), Message = $"[(Inner) {aggregate.InnerException.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + aggregate.InnerException.GetRealMessage() };
                    logMessage.Nested = logMessage.Nested.Concat(new[] { innerMessage }).ToArray();
                }
            }
            else
            {
                if (exception.InnerException != null)
                {
                    var innerMessage = new LogMessage() { Type = null, Time = null, Trace = new SerializableTrace(exception.InnerException, null, 1), Message = $"[(Inner) {exception.InnerException.GetType().ToString().Split(new[] { '.', '+' }).Last()}] " + exception.InnerException.GetRealMessage() };
                    logMessage.Nested = new[] { innerMessage };
                }
            }

            var writeException = Wrap.ExecuteSafe(() => Write(logMessage, options?.OutputWriter));
            if (writeException != null)
                Log.EnqueueExceptionSafe(exception, source: "Logger");
        }

        private static string GetRealMessage(this Exception exception)
        {
            string exceptionMessage = exception.Message;

            if (exception is Win32Exception win32Exception)
            {
                var rawMessage = new Win32Exception(win32Exception.NativeErrorCode).Message;
                if (rawMessage != win32Exception.Message)
                {
                    // Message has been set manually by the Win32Exception constructor, so append the valuable win32 error message
                    exceptionMessage = exceptionMessage.TrimEnd('.') + ": " + rawMessage;
                }
            }
            return exceptionMessage;
        }

        /// <summary>
        /// Write header metadata to log file. This deletes any previous <b>filePath</b> file if present.
        /// <br/><br/>Note that any normal write/enqueue method will automatically write the metadata if this was
        /// not called previously.
        /// </summary>
        public static void WriteMetadata(string filePath)
        {
            var exception = Wrap.ExecuteSafe(() =>
            {
                var logMessage = new LogMessage { FilePath = filePath, Type = LogType.Info, Message = null, Trace = null, Time = default, Data = null };

                Write(logMessage, null, true);
            });
            if (exception != null)
                Log.EnqueueExceptionSafe(exception, source: "Logger");
        }

        #endregion

        #region Public helper methods

        public static SerializableTrace GetCurrentTrace() => new SerializableTrace();

        #endregion

        #region Private methods

        private static object _lockObject = new object();

        private static void CheckLogThread()
        {
            lock (_lockObject)
            {
                if (_logThread != null && !_logThread.IsAlive)
                    _logThread = null;
                if (_logThread == null)
                    StartLoggerThread();
            }
        }

        private static void StartLoggerThread()
        {
            lock (_lockObject)
            {
                if (_logThread != null)
                    throw new Exception("Only one logging instance allowed.");

                _logThreadCancel = new CancellationTokenSource();
                _logThread = new Thread(ThreadLoop) { IsBackground = true, CurrentUICulture = CultureInfo.InvariantCulture };
                _logThread.Start();
            }
        }

        private static void EndLoggerThread()
        {
            lock (_lockObject)
            {
                _logThreadCancel.Cancel();
                if (!_logThread.Join(2000))
                    throw new TimeoutException("Log thread took too long to exit.");

                _logThread = null;
            }
        }

        private static void ThreadLoop()
        {
            foreach (var message in Queue.GetConsumingEnumerable(_logThreadCancel.Token))
            {
                Wrap.ExecuteSafe(() => Write(message));
            }
        }

        private static readonly ISerializer _serializer = new SerializerBuilder().WithTypeConverter(new Converters.DateTimeConverter()).WithTypeConverter(new Converters.TraceConverter()).WithTypeConverter(new Converters.StringConverter()).ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull).Build();

        private static void Write(LogMessage message, Output.OutputWriter outputWriter = null, bool metadataOnly = false)
        {
            Converters.TraceConverter.SourceOverride = message.SourceOverride;
            
            using var md5 = MD5.Create();

            var path = Wrap.ExecuteSafe(() =>
            {
                var fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(LogFileOverride ?? message.FilePath));

                if (!Directory.Exists(Path.GetDirectoryName(fullPath)))
                    Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

                return fullPath;
            });
            if (path.Failed)
            {
                EnqueueExceptionSafe(path.Exception, source: "Logger");
                return;
            }

            byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(path.Value));
            var hash = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();

            using (var mutex = new Mutex(false, "AME-File-" + hash))
            {
                try
                {
                    mutex.WaitOne();
                    
                    if (outputWriter != null)
                    {
                        long lineNumber = File.Exists(path.Value) ? Wrap.ExecuteSafe(() => File.ReadLines(path.Value).LongCount() + 2, -1).Value : 2;
                        outputWriter.WriteLineSafe(message.Type + $" | {Path.GetFileName(path.Value)}:{lineNumber}", message.Message);
                    }

                    int i;
                    for (i = 0; i != 10; i++)
                    {
                        StreamWriter writer = null;
                        try
                        {
                            string metadata = null;
                            if (!File.Exists(path.Value))
                            {
                                using (_ = File.Create(path.Value)) { }

                                FileInfo fileInfo = new FileInfo(path.Value);
                                FileSecurity fileSecurity = fileInfo.GetAccessControl();
                                fileSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                                    FileSystemRights.FullControl, AccessControlType.Allow));

                                fileInfo.SetAccessControl(fileSecurity);
                                
                                MetadataSource.Construct();
                                metadata = MetadataSource.Serialize(_serializer);
                            } else if (metadataOnly)
                            {
                                MetadataSource.Construct();
                                metadata = MetadataSource.Serialize(_serializer);
                            }
                            else
                            {
                                Wrap.ExecuteSafe(() => TrimLogFile(path.Value));
                            }
                            
                            writer = new StreamWriter(path.Value, !metadataOnly);

                            if (metadata != null)
                                writer.Write(metadata);

                            if (!metadataOnly)
                            {
                                var serialized = _serializer.Serialize(message);
                                if (serialized.Length > 10000)
                                {
                                    serialized = _serializer.Serialize(new LogMessage()
                                    {
                                        Message = "Log serialization exceeded 10000 characters.\r\nMessage: " + (message.Message.Length > 5000 ? message.Message.Take(5000) + "..." : message.Message) + (message.Trace == null ? string.Empty : "\r\nSource: " + message.Trace.Source),
                                        Type = LogType.Warning,
                                        Time = message.Time,
                                    });
                                }

                                writer.WriteLine("---"); // document separator
                                writer.Write(serialized);
                            }

                            writer.Flush();

                            break;
                        }
                        catch (Exception e)
                        {
                            if (_logThreadCancel.IsCancellationRequested)
                                return;

                            writer?.Dispose();
                            if (i == 8 && e is UnauthorizedAccessException ex)
                            {
                                EnqueueExceptionSafe(ex, null, "Logger", ("Path", path.Value));
                                path.Value += "x";
                            }
                            if (i == 9)
                                EnqueueExceptionSafe(e, null, "Logger", ("Path", path.Value));

                            Thread.Sleep(100);
                        }
                        finally
                        {
                            writer?.Dispose();
                        }
                    }
                }
                finally
                {
                    mutex.ReleaseMutex();
                }
            }
        }

        private static void TrimLogFile(string path)
        {
            const long maxBytes = 1 * 1024 * 1024; // 1MB
            var fileInfo = new FileInfo(path);

            if (fileInfo.Length > maxBytes)
            {
                Log.EnqueueSafe(LogType.Warning, "Log filesize exceeded 1MB.", new SerializableTrace("Logger"));

                const long bytesToRemoveMinimum = 100 * 1024; // 100KB
                const long startRemovingAtMinimum = 100 * 1024; // Start removing at ~100KB
                var remainingLog = new StringBuilder();
                bool shouldClearFile = false;

                using (var reader = new StreamReader(path))
                {
                    string line;
                    long totalBytesRead = 0;

                    // Collect bytes until we reach the start of block to be removed.
                    while ((line = reader.ReadLine()) != null)
                    {
                        totalBytesRead += Encoding.UTF8.GetByteCount(line + Environment.NewLine);

                        if (totalBytesRead >= startRemovingAtMinimum && line.StartsWith("---"))
                        {
                            break;
                        }

                        if (totalBytesRead < (maxBytes - bytesToRemoveMinimum))
                        {
                            remainingLog.AppendLine(line);
                        }
                        else
                        {
                            shouldClearFile = true;
                            break;
                        }
                    }

                    // Skip the block to be removed. Starts and ends with a line ---.
                    long bytesReadDuringRemoval = 0;
                    while (!shouldClearFile && (line = reader.ReadLine()) != null && (bytesReadDuringRemoval < bytesToRemoveMinimum || !line.StartsWith("---")))
                    {
                        bytesReadDuringRemoval += Encoding.UTF8.GetByteCount(line + Environment.NewLine);
                    }

                    // Read the rest of the file
                    if (!shouldClearFile && line != null) // Add the line beginning with --- to the remaining log
                    {
                        remainingLog.AppendLine(line);
                        remainingLog.AppendLine(reader.ReadToEnd());
                    }
                    else
                    {
                        shouldClearFile = true;
                    }
                }

                if (shouldClearFile)
                {
                    File.WriteAllText(path, string.Empty);
                }
                else
                {
                    using (var writer = new StreamWriter(path))
                    {
                        writer.Write(remainingLog.ToString());
                    }
                }
            }
        }

        internal static string RemoveParameterTypes(string name)
        {
            int firstPar = name.IndexOf('(');
            int lastPar = name.LastIndexOf(')');
    
            if (firstPar == -1 || lastPar == -1) return name;
    
            var paramsString = name.Substring(firstPar + 1, lastPar - firstPar - 1);
            var paramsArray = new List<string>();
            var curParam = new StringBuilder();
            int bracketCount = 0;

            foreach (var ch in paramsString)
            {
                if (ch == '<') { curParam.Append(ch); bracketCount++; }
                else if (ch == '>') { curParam.Append(ch); bracketCount--; }
                else if (ch == ',' && bracketCount == 0) 
                {
                    paramsArray.Add(curParam.ToString().Trim().Substring(curParam.ToString().Trim().LastIndexOf(' ') + 1));
                    curParam.Clear();
                }
                else curParam.Append(ch);
            }

            if (curParam.Length > 0)
                paramsArray.Add(curParam.ToString().Trim().Substring(curParam.ToString().Trim().LastIndexOf(' ') + 1));
            return name.Substring(0, firstPar + 1) + string.Join(", ", paramsArray) + ")";
        }

        #endregion

        #region Definitions

        public interface ILogMetadata
        {
            public string Serialize(ISerializer serializer);
            public void Construct();
        }
        
        [Serializable]
        public class LogMetadata : ILogMetadata
        {
            public DateTime CreationTime { get; set; }
            public string UserLanguage { get; set; }
            public string SystemMemory { get; set; }
            public int SystemThreads { get; set; }

            public void Construct()
            {
                UserLanguage = CultureInfo.InstalledUICulture.ToString();
                SystemMemory = StringUtils.HumanReadableBytes(Win32.SystemInfoEx.GetSystemMemoryInBytes());
                SystemThreads = Environment.ProcessorCount;
                CreationTime = DateTime.UtcNow;
            }

            public string Serialize(ISerializer serializer) => serializer.Serialize(this);
        }

        [Serializable]
        private class LogMessage
        {
            [NonSerialized] [YamlIgnore] public string FilePath;
            [CanBeNull] [YamlIgnore] public string SourceOverride { get; set; }
            public string Message { get; set; }
            [CanBeNull] public Dictionary<string, string> Data { get; set; }
            [CanBeNull] public LogType? Type { get; set; }
            [CanBeNull] public DateTime? Time { get; set; }
            [CanBeNull] public LogMessage[] Nested { get; set; }
            [CanBeNull] public SerializableTrace Trace { get; set; }
        }

        #endregion

        #region Converters

        private static class Converters
        {
            internal class DateTimeConverter : IYamlTypeConverter
            {
                public bool Accepts(Type type) => type == typeof(DateTime);

                public object ReadYaml(IParser parser, Type type)
                {
                    throw new NotImplementedException();
                }

                public void WriteYaml(IEmitter emitter, object value, Type type)
                {
                    if (value == null)
                        return;

                    var dateVal = ((DateTime)value).ToString("yyyy/MM/dd HH:mm:ss");
                    emitter.Emit(new Scalar(null, null, dateVal, ScalarStyle.Any, true, false));
                }
            }

            internal class TraceConverter : IYamlTypeConverter
            {
                public static string SourceOverride { get; set; } = null;
                
                public bool Accepts(Type type) => type == typeof(SerializableTrace);
                public object ReadYaml(IParser parser, Type type) => null;

                public void WriteYaml(IEmitter emitter, object value, Type type)
                {
                    if (!(value is SerializableTrace trace) || trace.Source == null)
                        return;

                    emitter.Emit(new Scalar(null, null, trace.ToString(SourceOverride), ScalarStyle.Literal, true, false));
                }
            }
            internal class StringConverter : IYamlTypeConverter
            {
                public bool Accepts(Type type) => type == typeof(string);
                public object ReadYaml(IParser parser, Type type) => null;

                public void WriteYaml(IEmitter emitter, object value, Type type)
                {
                    if (value == null)
                        return;
                    
                    var text = value.ToString();
                    
                    if (text.Contains('\n')) 
                        emitter.Emit(new Scalar(null, null, text, ScalarStyle.Literal, true, false));
                    else
                        emitter.Emit(new Scalar(null, null, text, ScalarStyle.Any, true, false));
                }
            }
        }

        #endregion
    }
}