using System;
using System.Runtime.Serialization;
using JetBrains.Annotations;

namespace Core.Miscellaneous
{
    public static class Serializables
    {

                [Serializable]
                public class SerializableType : ISerializable
                {
                    [NonSerialized] public readonly Type Type;
                    public string TypeName { get; set; }
        
                    public SerializableType(Type type)
                    {
                        Type = type;
                        TypeName = type.AssemblyQualifiedName;
                    }
        
                    protected SerializableType(SerializationInfo info, StreamingContext context)
                    {
                        TypeName = info.GetString("TypeName");
                        Type = Type.GetType(TypeName);
                    }
        
                    public void GetObjectData(SerializationInfo info, StreamingContext context) => info.AddValue("TypeName", TypeName);
                }
                
                [Serializable]
                public class SerializableValue : ISerializable
                {
                    public SerializableType Type { get; set; }
                    [CanBeNull] public object Value { get; set; }
        
                    public SerializableValue(Type type, [CanBeNull] object value)
                    {
                        Type = new SerializableType(type);
                        Value = value;
                    }
                    public SerializableValue([NotNull] object value)
                    {
                        Type = new SerializableType(value.GetType());
                        Value = value;
                    }
        
                    protected SerializableValue(SerializationInfo info, StreamingContext context)
                    {
                        Type = (SerializableType)info.GetValue("Type", typeof(SerializableType));
                        Value = info.GetValue("Value", Type.Type);
                    }
        
                    public void GetObjectData(SerializationInfo info, StreamingContext context)
                    {
                        info.AddValue("Type", Type);
                        info.AddValue("Value", Value);
                    }
                }
            }
}
