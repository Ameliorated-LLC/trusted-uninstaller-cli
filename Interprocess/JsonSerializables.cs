using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Core.Miscellaneous;
using JetBrains.Annotations;
using Core;
using TrustedUninstaller.Shared;

namespace Interprocess
{
    public partial class InterLink
    {
        [JsonSerializable(typeof(Playbook))]
        
        // Custom types
        [JsonSerializable(typeof(InterMessage))]
        [JsonSerializable(typeof(InterProgress))]
        [JsonSerializable(typeof(InterMessageReporter))]
        [JsonSerializable(typeof(InterCancellationTokenSource))]
        [JsonSerializable(typeof(Serializables.SerializableType))]
        [JsonSerializable(typeof(Serializables.SerializableValue))]

        [JsonSerializable(typeof(MethodMessage))]
        [JsonSerializable(typeof(TextMessage))]
        [JsonSerializable(typeof(ProgressMessage))]
        [JsonSerializable(typeof(MessageReportMessage))]
        [JsonSerializable(typeof(NodeRegistrationMessage))]
        [JsonSerializable(typeof(TokenCancellationMessage))]
        [JsonSerializable(typeof(ShutdownMessage))]

        [JsonSerializable(typeof(SerializableMethod))]
        [JsonSerializable(typeof(MessageResult))]
        [JsonSerializable(typeof(SerializableException))]
        [JsonSerializable(typeof(SerializableTrace))]

        [JsonSerializable(typeof(Void))]
        
        // Primitive types
        [JsonSerializable(typeof(byte))]
        [JsonSerializable(typeof(sbyte))]
        [JsonSerializable(typeof(int))]
        [JsonSerializable(typeof(uint))]
        [JsonSerializable(typeof(short))]
        [JsonSerializable(typeof(ushort))]
        [JsonSerializable(typeof(long))]
        [JsonSerializable(typeof(ulong))]
        [JsonSerializable(typeof(float))]
        [JsonSerializable(typeof(double))]
        [JsonSerializable(typeof(decimal))]
        [JsonSerializable(typeof(bool))]
        [JsonSerializable(typeof(byte?))]
        [JsonSerializable(typeof(sbyte?))]
        [JsonSerializable(typeof(int?))]
        [JsonSerializable(typeof(uint?))]
        [JsonSerializable(typeof(short?))]
        [JsonSerializable(typeof(ushort?))]
        [JsonSerializable(typeof(long?))]
        [JsonSerializable(typeof(ulong?))]
        [JsonSerializable(typeof(float?))]
        [JsonSerializable(typeof(double?))]
        [JsonSerializable(typeof(decimal?))]
        [JsonSerializable(typeof(bool?))]
        
        // Additional types
        [JsonSerializable(typeof(string))]
        [JsonSerializable(typeof(Enum))]
        [JsonSerializable(typeof(DateTime))]
        [JsonSerializable(typeof(DateTimeOffset))]
        [JsonSerializable(typeof(Guid))]
        [JsonSerializable(typeof(DateTime?))]
        [JsonSerializable(typeof(DateTimeOffset?))]
        [JsonSerializable(typeof(Guid?))]
        [JsonSerializable(typeof(Uri))]

        // TODO: On switch to .NET 8 with trimming
        internal partial class SourceGenerationContext // : JsonSerializerContext { }
        {
            public static SourceGenerationContext Default { get; } = new SourceGenerationContext();
            public static HashSet<Type> SerializableTypes { get; } = new HashSet<Type>
            {
                // Custom types
                typeof(InterMessage),
                typeof(InterProgress),
                typeof(InterMessageReporter),
                typeof(InterCancellationTokenSource),
                typeof(Serializables.SerializableType),
                typeof(Serializables.SerializableValue),

                typeof(MethodMessage),
                typeof(TextMessage),
                typeof(ProgressMessage),
                typeof(MessageReportMessage),
                typeof(NodeRegistrationMessage),
                typeof(TokenCancellationMessage),
                typeof(ShutdownMessage),

                typeof(SerializableMethod),
                typeof(MessageResult),
                typeof(SerializableException),
                typeof(SerializableTrace),
                
                typeof(Void),

                // Primitive types
                typeof(byte),
                typeof(sbyte),
                typeof(int),
                typeof(uint),
                typeof(short),
                typeof(ushort),
                typeof(long),
                typeof(ulong),
                typeof(float),
                typeof(double),
                typeof(decimal),
                typeof(bool),
                typeof(byte?),
                typeof(sbyte?),
                typeof(int?),
                typeof(uint?),
                typeof(short?),
                typeof(ushort?),
                typeof(long?),
                typeof(ulong?),
                typeof(float?),
                typeof(double?),
                typeof(decimal?),
                typeof(bool?),

                // Additional types
                typeof(string),
                typeof(Enum),
                typeof(DateTime),
                typeof(DateTimeOffset),
                typeof(Guid),
                typeof(DateTime?),
                typeof(DateTimeOffset?),
                typeof(Guid?),
                typeof(Uri)
            };

            [CanBeNull]
            public object GetTypeInfo(Type type)
            {
                if (SerializableTypes.Contains(type) || (type.IsArray && SerializableTypes.Contains(type.GetElementType())) || type.IsEnum)
                    return new object();

                return null;
            }
        }
    }
 
}