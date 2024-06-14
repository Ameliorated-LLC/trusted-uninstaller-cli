using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Reflection.Metadata;
using System.Runtime.ExceptionServices;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Core.Miscellaneous;
using JetBrains.Annotations;
using Core;
using Expression = System.Linq.Expressions.Expression;

namespace Interprocess
{
    public static partial class InterLink
    {
        #region Serialzier

        internal static JsonSerializerOptions _serializerOptions = new JsonSerializerOptions()
        {
            Converters =
            {
                new SerializableExceptionConverter(),
                new SerializableValueConverter(),
                new SerializableTypeConverter(),
            }
        };

        #region Converters

        public class SerializableExceptionConverter : JsonConverter<SerializableException>
        {
            public override SerializableException Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new JsonException();
                }

                var serializableException = new SerializableException(null);

                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndObject)
                    {
                        serializableException.OnDeserialized();
                        return serializableException;
                    }

                    if (reader.TokenType == JsonTokenType.PropertyName)
                    {
                        var propertyName = reader.GetString();
                        reader.Read();
                        switch (propertyName)
                        {
                            case "Trace":
                                serializableException.Trace = JsonSerializer.Deserialize<SerializableTrace>(ref reader, options);
                                break;
                            case "OriginalTraceString":
                                serializableException.OriginalTraceString = reader.GetString();
                                break;
                            case "OriginalType":
                                serializableException.OriginalType = JsonSerializer.Deserialize<Serializables.SerializableType>(ref reader, options);
                                break;
                            case "Message":
                                serializableException.Message = reader.GetString();
                                break;
                            case "InnerException":
                                serializableException.InnerException = reader.TokenType == JsonTokenType.Null ? null : JsonSerializer.Deserialize<SerializableException>(ref reader, options);
                                break;
                            case "AggregateInnerExceptions":
                                serializableException.AggregateInnerExceptions = reader.TokenType == JsonTokenType.Null ? null : JsonSerializer.Deserialize<SerializableException[]>(ref reader, options);
                                break;
                        }
                    }
                }

                throw new JsonException();
            }

            public override void Write(Utf8JsonWriter writer, SerializableException value, JsonSerializerOptions options)
            {
                writer.WriteStartObject();

                writer.WritePropertyName("Trace");
                JsonSerializer.Serialize(writer, value.Trace, options);

                writer.WritePropertyName("OriginalTraceString");
                writer.WriteStringValue(value.OriginalTraceString);

                writer.WritePropertyName("OriginalType");
                JsonSerializer.Serialize(writer, value.OriginalType, options);

                writer.WritePropertyName("Message");
                writer.WriteStringValue(value.Message);

                writer.WritePropertyName("InnerException");
                JsonSerializer.Serialize(writer, value.InnerException, options);

                writer.WritePropertyName("AggregateInnerExceptions");
                JsonSerializer.Serialize(writer, value.AggregateInnerExceptions, options);

                writer.WriteEndObject();
            }
        }
        
        private class SerializableTypeConverter : JsonConverter<Serializables.SerializableType>
        {
            public override Serializables.SerializableType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new JsonException();
                }

                Type type = null;
                string typeName;

                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndObject)
                        return new Serializables.SerializableType(type);

                    if (reader.TokenType == JsonTokenType.PropertyName)
                    {
                        string propertyName = reader.GetString();
                        reader.Read();

                        if (propertyName == "TypeName")
                        {
                            typeName = reader.GetString();
                            type = Type.GetType(typeName!);
                        }
                    }
                }

                throw new JsonException();
            }

            public override void Write(Utf8JsonWriter writer, Serializables.SerializableType value, JsonSerializerOptions options)
            {
                writer.WriteStartObject();
                writer.WriteString("TypeName", value.TypeName);
                writer.WriteEndObject();
            }
        }

        private class SerializableValueConverter : JsonConverter<Serializables.SerializableValue>
        {
            public override Serializables.SerializableValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    throw new JsonException();
                }

                Type type = null;
                object value = null;

                while (reader.Read())
                {
                    if (reader.TokenType == JsonTokenType.EndObject)
                        return new Serializables.SerializableValue(type, value);

                    if (reader.TokenType == JsonTokenType.PropertyName)
                    {
                        string propertyName = reader.GetString();
                        reader.Read();

                        if (propertyName == "Type")
                        {
                            var serializableType = JsonSerializer.Deserialize<Serializables.SerializableType>(ref reader, options);
                            type = serializableType.Type;
                        }
                        else if (propertyName == "Value")
                        {
                            if (type != null)
                            {
                                value = JsonSerializer.Deserialize(ref reader, type, options);
                            }
                        }
                    }
                }

                throw new JsonException();
            }

            public override void Write(Utf8JsonWriter writer, Serializables.SerializableValue value, JsonSerializerOptions options)
            {
                writer.WriteStartObject();

                writer.WritePropertyName("Type");
                JsonSerializer.Serialize(writer, value.Type, options);

                if (value.Type.Type != typeof(void))
                {
                    writer.WritePropertyName("Value");
                    JsonSerializer.Serialize(writer, value.Value, value.Type.Type, options);
                }
                
                writer.WriteEndObject();
            }
        }

        #endregion

        #endregion

        #region Definitions

        #region Public

        [Serializable]
        public class InterCancellationTokenSource : IInterObject, IDisposable, IJsonOnDeserialized
        {
            public InternalLevel SourceLevel { get; set; } = ApplicationLevel;
            public Guid ID { get; set; } = Guid.NewGuid();
            public bool IsCancellationRequested { get; set; } = false;

            public InterCancellationTokenSource() : this(new CancellationTokenSource()) {}

            public InterCancellationTokenSource(CancellationTokenSource underlyingToken)
            {
                _underlyingToken = underlyingToken;
                
                if (SourceLevel == ApplicationLevel)
                    TokenTasks[ID] = this;
            }

            #region NonSerialized Logic

            private CancellationTokenSource _underlyingToken;
            private List<InternalLevel> _targets = new List<InternalLevel>();

            [JsonIgnore] public CancellationToken Token => _underlyingToken.Token;

            private object _cancellationLock = new object();
            public void Cancel() => Cancel(ApplicationLevel);

            internal void Cancel(InternalLevel cancelSource)
            {
                lock (_cancellationLock)
                {
                    if (IsCancellationRequested)
                        return;

                    IsCancellationRequested = true;
                }

                var localCancelException = Wrap.ExecuteSafe(() => _underlyingToken.Cancel());
                var interCancelException = Wrap.ExecuteSafe(() =>
                {
                    if (SourceLevel != ApplicationLevel && _wasDeserialized)
                    {
                        MessageWriteQueue.Add(new TokenCancellationMessage(SourceLevel, ApplicationLevel)
                        {
                            TokenID = ID,
                            SourceLevel = SourceLevel,
                        });
                    }
                    else
                    {
                        foreach (var target in _targets.Where(target => target != cancelSource))
                        {
                            MessageWriteQueue.Add(new TokenCancellationMessage(target, ApplicationLevel)
                            {
                                TokenID = ID,
                                SourceLevel = SourceLevel,
                            });
                        }
                    }
                });
                if (localCancelException != null || interCancelException != null)
                    ExceptionDispatchInfo.Capture(localCancelException ?? interCancelException).Throw();
            }

            public void BeforeSend(InternalLevel targetLevel)
            {
                if (targetLevel == SourceLevel)
                    throw new InvalidOperationException($"Target level ({targetLevel.ToString()}) for an InterCancellationTokenSource must not be the same as the source level ({SourceLevel}).");
                _targets.Add(targetLevel);
            }

            public void OnCompleted(InternalLevel targetLevel) => _targets.Remove(targetLevel);

            private bool _wasDeserialized = false;
            public void OnDeserialized()
            {
                if (IsCancellationRequested)
                    _underlyingToken.Cancel();

                _wasDeserialized = true;
            }

            public void Dispose()
            {
                if (!_wasDeserialized)
                    TokenTasks.TryRemove(ID, out _);

                _underlyingToken.Dispose();
            }

            #endregion
        }

        [Serializable]
        public class InterProgress : Progress<decimal>, IDisposable, IProgress<decimal>
        {
            public Guid ID { get; private set; }
            public InternalLevel Receiver { get; set; }
            public decimal Maximum { get; set; } = 100m;

            [JsonConstructor]
            public InterProgress(Guid id, InternalLevel receiver)
            {
                ID = id;
                Receiver = receiver;
            }
            public InterProgress(Action<decimal> handler) : base(handler)
            {
                Receiver = ApplicationLevel;
                ID = Guid.NewGuid();
                ProgressTasks[ID] = this;
            }

            #region NonSerialized Logic

            public void Report(decimal value)
            {
                if (value < 0m)
                    throw new InvalidOperationException("Reported progress must not be less than zero");

                if (ApplicationLevel == Receiver)
                    OnProgressReceived(value);
                else
                    SendProgress(value);
            }

            public void OnProgressReceived(decimal progress)
            {
                if (ApplicationLevel != Receiver)
                    throw new InvalidOperationException($"OnProgressReceived must be called from the receiving node ({Receiver}).");
                
                if (progress < 0m || progress > Maximum)
                    return;
                
                base.OnReport(progress);
            }

            private void SendProgress(decimal value)
            {
                var interMessage = new ProgressMessage(Receiver, ApplicationLevel)
                {
                    ProgressID = ID,
                    Value = value,
                };
                MessageWriteQueue.Add(interMessage);
            }

            public new void OnReport(decimal progress) => throw new NotImplementedException();

            public void Dispose()
            {
                if (ApplicationLevel == Receiver)
                {
                    ProgressTasks.TryRemove(ID, out _);
                }
            }

            #endregion
        }
        
        [Serializable]
        public class InterMessageReporter : Progress<string>, IDisposable, IProgress<string>
        {
            public Guid ID { get; private set; }
            public InternalLevel Receiver { get; set; }

            [JsonConstructor]
            public InterMessageReporter(Guid id, InternalLevel receiver)
            {
                ID = id;
                Receiver = receiver;
            }
            public InterMessageReporter(Action<string> handler) : base(handler)
            {
                Receiver = ApplicationLevel;
                ID = Guid.NewGuid();
                MessageReportTasks[ID] = this;
            }

            #region NonSerialized Logic

            public void Report(string value)
            {
                if (ApplicationLevel == Receiver)
                    OnMessageReceived(value);
                else
                    SendProgress(value);
            }

            public void OnMessageReceived(string progress)
            {
                if (ApplicationLevel != Receiver)
                    throw new InvalidOperationException($"OnProgressReceived must be called from the receiving node ({Receiver}).");
                
                base.OnReport(progress);
            }

            private void SendProgress(string value)
            {
                var interMessage = new MessageReportMessage(Receiver, ApplicationLevel)
                {
                    ReporterID = ID,
                    Value = value,
                };
                MessageWriteQueue.Add(interMessage);
            }

            public new void OnReport(string progress) => throw new NotImplementedException();

            public void Dispose()
            {
                if (ApplicationLevel == Receiver)
                {
                    MessageReportTasks.TryRemove(ID, out _);
                }
            }

            #endregion
        }

        #endregion

        #region Private
        
        [JsonDerivedType(typeof(MethodMessage), 0)]
        [JsonDerivedType(typeof(TextMessage), 1)]
        [JsonDerivedType(typeof(ProgressMessage), 2)]
        [JsonDerivedType(typeof(MessageReportMessage), 3)]
        [JsonDerivedType(typeof(TokenCancellationMessage), 4)]
        [JsonDerivedType(typeof(NodeRegistrationMessage), 5)]
        [JsonDerivedType(typeof(ShutdownMessage), 6)]
        private class InterMessage
        {
            [JsonConstructor]
            public InterMessage(Guid messageId) => MessageID = messageId;
            
            protected InterMessage() { }
            protected InterMessage(InternalLevel targetLevel, InternalLevel callerLevel)
            {
                TargetLevel = targetLevel;
                CallerLevel = callerLevel;
            }
            
            public Guid MessageID { get; set; }

            public InternalLevel TargetLevel { get; set; }
            public InternalLevel CallerLevel { get; set; }

            [NotNull] public MessageResult Result { get; set; } = MessageResult.Empty;

            [NonSerialized] internal readonly SemaphoreSlim Processed = new SemaphoreSlim(0, 1);
            
            [NonSerialized] internal byte[] JsonHash = {};
            [NonSerialized] internal bool PendingVerification = false;
            [NonSerialized] internal bool Enqueued = false;
            [NonSerialized] internal int EnqueueTimeout;
            [NonSerialized] internal bool Sent = false;
            [NonSerialized] internal bool LogExceptions = false;
        }
        
        private class MethodMessage : InterMessage
        {
            [JsonConstructor]
            public MethodMessage(Guid messageId) => MessageID = messageId;
            public MethodMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public SerializableMethod Method { get; set; } = null;
        }
        private class TextMessage : InterMessage
        {
            [JsonConstructor]
            public TextMessage(Guid messageId) => MessageID = messageId;
            public TextMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public string Text { get; set; } = null;
        }
        private class ProgressMessage : InterMessage
        {
            [JsonConstructor]
            public ProgressMessage(Guid messageId) => MessageID = messageId;
            public ProgressMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public Guid ProgressID { get; set; }
            public decimal Value { get; set; }
        }
        private class MessageReportMessage : InterMessage
        {
            [JsonConstructor]
            public MessageReportMessage(Guid messageId) => MessageID = messageId;
            public MessageReportMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public Guid ReporterID { get; set; }
            public string Value { get; set; }
        }
        
        private class TokenCancellationMessage : InterMessage
        {
            [JsonConstructor]
            public TokenCancellationMessage(Guid messageId) => MessageID = messageId;
            public TokenCancellationMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public Guid TokenID { get; set; }
            public InternalLevel SourceLevel { get; set; }
        }
        private class NodeRegistrationMessage : InterMessage
        {
            [JsonConstructor]
            public NodeRegistrationMessage(Guid messageId) => MessageID = messageId;
            public NodeRegistrationMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
            
            public InternalLevel Level { get; set; }
            public int ProcessID { get; set; }
        }
        private class ShutdownMessage : InterMessage
        {
            [JsonConstructor]
            public ShutdownMessage(Guid messageId) => MessageID = messageId;
            public ShutdownMessage(InternalLevel targetLevel, InternalLevel callerLevel) : base(targetLevel, callerLevel) { }
        }

        [Serializable]
        public class SerializableMethod
        {
            public Serializables.SerializableType ParentClass { get; set; }
            public string MethodName { get; set; }
            public Serializables.SerializableValue[] Parameters { get; set; } = Array.Empty<Serializables.SerializableValue>();
            public Serializables.SerializableType[] GenericTypes { get; set; } = Array.Empty<Serializables.SerializableType>();

            [NonSerialized] internal MethodInfo Method;
        }

        [Serializable]
        private class MessageResult
        {
            public static readonly MessageResult Empty = new MessageResult();
            
            public Guid MessageID { get; set; }
            public InternalLevel MessageCallerLevel { get; set; }
            public InternalLevel MessageTargetLevel { get; set; }

            private MessageResult() { }
            [JsonConstructor]
            public MessageResult(Guid messageId) => MessageID = messageId;
            public MessageResult(Guid messageId, InternalLevel messageTargetLevel, InternalLevel messageCallerLevel, Serializables.SerializableValue value)
            {
                MessageID = messageId;
                MessageTargetLevel = messageTargetLevel;
                MessageCallerLevel = messageCallerLevel;
                Value = value;
                Exception = null;
            }
            
            public MessageResult(Guid messageId, InternalLevel messageTargetLevel, InternalLevel messageCallerLevel, SerializableException exception)
            {
                MessageID = messageId;
                MessageTargetLevel = messageTargetLevel;
                MessageCallerLevel = messageCallerLevel;
                Value = null;
                Exception = exception;
            }
            
            [CanBeNull] public Serializables.SerializableValue Value { get; set; } = null;
            [CanBeNull] public SerializableException Exception { get; set; } = null;
            
            [NonSerialized] internal byte[] JsonHash = null;
            [NonSerialized] internal bool PendingVerification = false;
        }

        public enum VerificationType
        {
            Message,
            Result,
        }
        public class VerificationRequest
        {
            public VerificationType Type { get; set; }
            public Guid IdToVerify { get; set; }
            public byte[] JsonHash { get; set; }
            public InternalLevel CallerLevel { get; set; }
            public InternalLevel TargetLevel { get; set; }
        }
        
        #endregion

        #endregion
    }
}