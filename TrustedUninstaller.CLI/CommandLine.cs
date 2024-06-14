using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.Internal;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Principal;
using System.Windows;
using Core;
using Interprocess;
using JetBrains.Annotations;
using Exception = System.Exception;

namespace TrustedUninstaller.CLI
{
    public static class CommandLine
    {
        #region Deserializers
        
        public class Interprocess : IArgumentData
        {
            [Required] [DefaultArgument] public Level Level { get; set; }
            [Required] public Mode Mode { get; set; }
            [CanBeNull] public NodeData[] Nodes { get; set; } = null;
            public int Host { get; set; } = -1;

            public class NodeData
            {
                public InterLink.InternalLevel Level { get; set; }
                public int ProcessID { get; set; }
            }
        }


        public class Execute : IArgumentData
        {
            [Required] [DefaultArgument] public CommandType Command { get; set; }
            
            public enum CommandType
            {
                [RequiresArgumentData("RunData")] Run,
                Delete,
            }
            
            [RequiredArgumentData] public Run RunData { get; set; }

            public class Run : IArgumentData
            {
                [Required] [DefaultArgument] public string File { get; set; }
            }
        }
        
        #endregion

        #region Deserialization
        
        public static string SerializeArgument([NotNull] object value)
        {
            Type propertyType = value.GetType();

            if (propertyType.IsValueTuple())
            {
                var properties = propertyType.GetFields();
                var serializedProperties = new List<string>();

                foreach (var property in properties)
                {
                    var propertyValue = property.GetValue(value);
                    serializedProperties.Add($"{property.Name}={propertyValue?.ToString().Replace(":", "::")}");
                }
        
                return string.Join(":", serializedProperties);
            }
            else
            {
                throw new ArgumentException("Expected a ValueTuple", nameof(value));
            }
        }

        [CanBeNull]
        public static IArgumentData ParseArguments() => ParseArguments(Environment.GetCommandLineArgs().Skip(1).ToArray());
        [CanBeNull]
        public static IArgumentData ParseArguments(string[] args)
        {
            if (args.Length == 0)
                return null;
            
            var dataClasses = typeof(CommandLine).GetNestedTypes().Where(x => x.GetInterfaces().Contains(typeof(IArgumentData))).ToArray();
            var dataClass = dataClasses.FirstOrDefault(x => x.Name.Equals($"{args[0]}"));
            if (dataClass == null)
                throw new SerializationException("First argument must be one of the following: \r\n" + String.Join(Environment.NewLine, dataClasses.Select(x => x.Name)));

            var argsToParse = args.Skip(1).ToList();
            var data = (IArgumentData)Activator.CreateInstance(dataClass);

            return DeserializeArguments(argsToParse, data);
        }

        private static IArgumentData DeserializeArguments(List<string> args, IArgumentData result)
        {
            var properties = result.GetType().GetProperties();

            PropertyInfo defaultProperty = null;
            if (args.Count > 0 && !args[0].StartsWith("--"))
            {
                defaultProperty = properties.FirstOrDefault(x => x.GetCustomAttribute(typeof(DefaultArgumentAttribute)) != null);
                if (defaultProperty == null)
                    throw new SerializationException($"Unexpected argument '{args[0]}'.");
            }

            List<string> propertiesParsed = new List<string>();
            bool passedArgument = true;
            for (int i = 0; i < args.Count; i++)
            {
                if (!args[i].StartsWith("--"))
                {
                    if (i == 0 && defaultProperty != null)
                        i--;
                    else
                    {
                        if (passedArgument)
                            throw new SerializationException($"Expected an argument starting with '--', instead got '{args[i]}'. Make sure to quote any arguments that contain spaces or special characters.");

                        passedArgument = true;
                        continue;
                    }
                }
                passedArgument = false;

                var property = defaultProperty ?? properties.FirstOrDefault(x => x.Name.Equals(args[i].Substring(2), StringComparison.OrdinalIgnoreCase) && x.GetCustomAttribute(typeof(RequiredArgumentDataAttribute)) == null);
                if (property == null)
                    throw new SerializationException($"Unrecognized argument '{args[i]}'.");
                if (propertiesParsed.Contains(property.Name))
                    throw new SerializationException($"Duplicate argument '{args[i]}'.");
                
                defaultProperty = null;
                
                propertiesParsed.Add(property.Name);

                if (property.PropertyType == typeof(bool) && (args.Count - 1 == i || args[i + 1].StartsWith("--")))
                {
                    DeserializeArgument(property.PropertyType, "true", result);
                    continue;
                }
                
                if (args.Count - 1 == i)
                    throw new SerializationException($"An empty value is not valid for '--{property.Name}'.");
                    
                if (property.PropertyType.IsEnum)
                {
                    var converter = TypeDescriptor.GetConverter(property.PropertyType);

                    var enumValue = Wrap.ExecuteSafe(() => converter.ConvertFromString(args[i + 1])).Value;
                    if (enumValue == null)
                        throw new SerializationException($"Argument '{args[i + 1]}' must be one of the following: \r\n" + String.Join(Environment.NewLine, Enum.GetNames(property.PropertyType)));

                    property.SetValue(result, enumValue);
                    if (!EnumValueHasAttribute(property.PropertyType, enumValue, typeof(RequiresArgumentDataAttribute)))
                        continue;

                    var attribute = (RequiresArgumentDataAttribute)Attribute.GetCustomAttribute(
                        property.PropertyType.GetField(enumValue.ToString()), typeof(RequiresArgumentDataAttribute));

                    var requiredDataProperty = properties.FirstOrDefault(x => x.Name == attribute.RequiredProperty);
                    if (requiredDataProperty == null)
                        throw new SerializationException($"Required property '{attribute.RequiredProperty}' not found in class '{result.GetType().Name}'.");

                    if (!typeof(IArgumentData).IsAssignableFrom(requiredDataProperty.PropertyType))
                        throw new SerializationException($"Required property '{attribute.RequiredProperty}' type does not implement the 'IArgumentData' interface.");

                    var requiredData = (IArgumentData)Activator.CreateInstance(requiredDataProperty.PropertyType);
                    DeserializeArguments(args.Skip(args.FindIndex(x => ReferenceEquals(x, args[i + 1])) + 1).ToList(), requiredData);
                    requiredDataProperty.SetValue(result, requiredData);
                    break;
                }
                else
                    property.SetValue(result, DeserializeArgument(property.PropertyType, args[i + 1], result));
            }

            var requiredProperty = properties.FirstOrDefault(x => x.GetCustomAttribute(typeof(RequiredAttribute)) != null && !propertiesParsed.Contains(x.Name));
            if (requiredProperty != null)
                throw new SerializationException($"Missing required argument '--{requiredProperty.Name}'");

            return result;
        }

        [NotNull]
        private static object DeserializeArgument(Type propertyType, string value, IArgumentData data)
        {
            if (propertyType.IsArray)
            {
                var itemType = propertyType.GetElementType();
                    
                if (itemType!.IsArray)
                    throw new SerializationException("Arrays of arrays are not supported.");
                
                var itemValues = value.Split(',');
                List<object> items = new List<object>();
                foreach (var itemValue in itemValues)
                {
                    items.Add(DeserializeArgument(itemType, itemValue, data));
                }
                Array itemsOfType = Array.CreateInstance(itemType!, items.Count);

                for (int i = 0; i < items.Count; i++)
                {
                    itemsOfType.SetValue(Convert.ChangeType(items[i], itemType), i);
                }

                return itemsOfType;
            }
            if (propertyType == typeof(string))
            {
                return value;
            }
            else if (propertyType == typeof(bool))
            {
                if (!bool.TryParse(value, out bool boolValue))
                    throw new SerializationException($"Expected 'true' or 'false' for '--{propertyType.Name}'."); 
                
                return boolValue;
            } else if (propertyType == typeof(int))
            {
                if (!int.TryParse(value, out int intValue))
                    throw new SerializationException($"Expected a number for '--{propertyType.Name}'.");

                return intValue;
            } else if (propertyType == typeof(long))
            {
                if (!long.TryParse(value, out long longValue))
                    throw new SerializationException($"Expected a number for '--{propertyType.Name}'.");

                return longValue;
            } else if (propertyType.IsClass)
            {
                var instance = Activator.CreateInstance(propertyType);
                foreach (var item in value.Split(':'))
                {
                    var parts = item.Split('=');
                    var propName = parts[0].Trim();
                    var propValue = (parts.Length > 1) ? parts[1].Trim().Replace("::", ":") : null;

                    if (string.IsNullOrWhiteSpace(propValue)) continue;

                    var property = propertyType.GetProperty(propName, BindingFlags.Public | BindingFlags.Instance);

                    if (property != null)
                    {
                        object convertedValue = null;
                        if (property.PropertyType.IsEnum)
                            convertedValue = Enum.Parse(property.PropertyType, propValue);
                        else
                            convertedValue = Convert.ChangeType(propValue, property.PropertyType);

                        property.SetValue(instance, convertedValue);
                    }
                }
                return instance;
            }
                
            throw new SerializationException($"Unexpected type '{propertyType.Name}' of property in class '{data.GetType().Name}'.");
        }

        public static bool EnumValueHasAttribute(Type enumType, object enumValue, Type attributeType)
        {
            var fieldInfo = enumType.GetField(enumValue.ToString());
            var attribute = (Attribute)Attribute.GetCustomAttribute(fieldInfo, attributeType);
            return attribute != null;
        }
        
        #endregion
        
        #region Definitions

        public interface IArgumentData { }
        
        [AttributeUsage(AttributeTargets.Field)]
        public class RequiresArgumentDataAttribute : Attribute
        {
            public string RequiredProperty { get; set; }

            public RequiresArgumentDataAttribute(string requiredProperty) =>
                RequiredProperty = requiredProperty;
        }
        
        public class RequiredArgumentDataAttribute : Attribute { }
        
        public class DefaultArgumentAttribute : Attribute { }
        
        public class ArgumentDictionary<TKey, TValue>
        {
            private Dictionary<TKey, TValue> _dictionary = new Dictionary<TKey, TValue>();
            private List<TKey> _index = new List<TKey>();

            public void Add(TKey key, TValue value)
            {
                _dictionary.Add(key, value);
                _index.Add(key);
            }

            public bool TryGetValueAfterIndex(int index, TKey key, out TValue value)
            {
                bool found = _dictionary.TryGetValue(key, out value);
                if (!found)
                    return false;

                int indexPosition = _index.IndexOf(key);
                if (indexPosition > index)
                {
                    return true;
                }

                throw new SerializationException($"Argument '--{key}' must come after '--{_index[index]}'.");
            }

            public int GetIndex(TKey key) => _index.IndexOf(key);

            public TValue this[TKey key]
            {
                get { return _dictionary[key]; }
                private set => _dictionary[key] = value;
            }
        }

        #endregion
        
    }
}