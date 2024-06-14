using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using TrustedUninstaller.Shared;

namespace Core.Miscellaneous
{
    public abstract class XmlDeserializable : IXmlSerializable
    {
        public class XmlAllowInlineArrayItemAttribute : Attribute { }

        public class XmlRequiredAttribute : Attribute
        {
            public bool AllowEmptyString { get; set; }
            public XmlRequiredAttribute() => AllowEmptyString = true;
            public XmlRequiredAttribute(bool allowEmptyString) => AllowEmptyString = allowEmptyString;
        }
        
        [Obsolete("XmlDeserializable does not support XmlInclude.")]
        public class XmlIncludeAttribute : Attribute { }

        /// <summary>
        /// This method gets called upon after deserialization, but before Deserialize returns. This is a good place to throw exceptions to the Deserialize call.
        /// </summary>
        public virtual void Validate() { }

        public XmlSchema GetSchema() => null;

        public void ReadXml(XmlReader reader)
        {
            var properties = this.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance);

            var classType = reader.Name;
            List<string> assignedProperties = new List<string>();
            if (reader.HasAttributes)
            {
                while (reader.MoveToNextAttribute())
                {
                    var property = properties.FirstOrDefault(x => x.GetCustomAttribute<XmlIgnoreAttribute>() == null && (x.GetCustomAttributes<XmlAttributeAttribute>().FirstOrDefault(attr => !string.IsNullOrEmpty(attr.AttributeName) && attr.AttributeName == reader.Name) != null || (x.Name  == reader.Name && x.GetCustomAttribute<XmlAttributeAttribute>() != null))) ??
                        throw new XmlException($"Unrecognized attribute '{reader.Name}'");

                    if (assignedProperties.Contains(property.Name))
                        throw new XmlException($"Duplicate assignment for property '{property.Name}'");
                    assignedProperties.Add(property.Name);

                    property.SetValue(this, ReadContentValue(reader, property.PropertyType));
                }
            }

            while (true)
            {
                if (!MoveToNextElement(reader, classType))
                {
                    var requiredProperty = properties.FirstOrDefault(x =>
                        x.GetCustomAttribute<XmlIgnoreAttribute>() == null && x.GetCustomAttribute<XmlRequiredAttribute>() != null && (!assignedProperties.Contains(x.Name) || (x.PropertyType == typeof(string) && !x.GetCustomAttribute<XmlRequiredAttribute>().AllowEmptyString && string.IsNullOrWhiteSpace((string)x.GetValue(this)))));
                    if (requiredProperty != null && !assignedProperties.Contains(requiredProperty.Name)) 
                        throw new XmlException($"Required property '{requiredProperty.Name}' must be set.");
                    else if (requiredProperty != null)
                        throw new XmlException($"Property '{requiredProperty.Name}' must not be empty.");
                    
                    Validate();
                    return;
                }

                var property = properties.FirstOrDefault(x => x.GetCustomAttribute<XmlIgnoreAttribute>() == null && (x.GetCustomAttributes<XmlElementAttribute>().FirstOrDefault(attr => !string.IsNullOrEmpty(attr.ElementName) && attr.ElementName == reader.Name) != null || x.Name  == reader.Name)) ?? throw new XmlException($"Unrecognized element '{reader.Name}'");
                var elementName = string.IsNullOrEmpty(property.GetCustomAttribute<XmlElementAttribute>()?.ElementName) ? property.Name : property.GetCustomAttribute<XmlElementAttribute>()?.ElementName;
                
                if (!property.PropertyType.IsClass && reader.HasAttributes)
                    throw new XmlException($"Unexpected attributes found on XML element '{elementName}'");
                if (property.GetCustomAttribute<XmlAttributeAttribute>() != null && property.GetCustomAttribute<XmlElementAttribute>() == null)
                    throw new XmlException($"Property '{property.Name}' must be assigned as an XML attribute.");

                if (assignedProperties.Contains(property.Name))
                    throw new XmlException($"Duplicate assignment for property '{property.Name}'");
                assignedProperties.Add(property.Name);

                if (property.PropertyType.IsArray)
                {
                    IList arrayList = null;
                    var arrayItemType = property.PropertyType.GetElementType()!;
                    var arrayItemTypes = property.GetCustomAttributes(typeof(XmlArrayItemAttribute)).OfType<XmlArrayItemAttribute>().Select(x => x.Type).ToList();
                    arrayItemTypes.Add(arrayItemType);

                    reader.Read();
                    if (reader.NodeType == XmlNodeType.Text)
                    {
                        if (property.GetCustomAttribute<XmlAllowInlineArrayItemAttribute>() == null)
                            throw new XmlException($"Element '{elementName}' must be an array, not a single value.");

                        arrayList = Array.CreateInstance(arrayItemType, 1);
                        arrayList[0] = ReadContentValue(reader, arrayItemType);
                        property.SetValue(this, arrayList);
                    }

                    while (true)
                    {
                        if (!MoveToNextElement(reader, elementName))
                            break;

                        if (arrayList == null)
                            arrayList = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(new[] { property.PropertyType.GetElementType() }));

                        arrayList.Add(ReadElementValue(reader, arrayItemTypes));
                    }
                    if (arrayList != null)
                    {
                        Array array = Array.CreateInstance(arrayItemType, arrayList.Count);
                        arrayList.CopyTo(array, 0);
                        property.SetValue(this, array);
                    }
                }
                else
                    property.SetValue(this, ReadElementValue(reader, property.PropertyType));
            }
        }
        public void WriteXml(XmlWriter writer) => new XmlSerializer(this.GetType()).Serialize(writer, this);
        private static object ReadElementValue(XmlReader reader, Type type)
        {
            type = Nullable.GetUnderlyingType(type) ?? type;
            if (type.IsEnum)
                return Enum.Parse(type, reader.ReadElementContentAsString());
            if (type == typeof(Guid))
                return Guid.Parse(reader.ReadElementContentAsString());
            if (type.IsClass && type != typeof(string))
            {
                var serializer = new XmlSerializer(type, new XmlRootAttribute(reader.Name));
                try
                {
                    return serializer.Deserialize(reader);
                }
                catch (InvalidOperationException e)
                {
                    if (e.InnerException == null)
                        throw;
                    throw e.InnerException;
                }
            }

            return reader.ReadElementContentAs(type, null);
        }
        private static object ReadContentValue(XmlReader reader, Type type)
        {
            type = Nullable.GetUnderlyingType(type) ?? type;
            if (type.IsEnum)
                return Enum.Parse(type, reader.ReadContentAsString());
            if (type == typeof(Guid))
                return Guid.Parse(reader.ReadContentAsString());

            return reader.ReadContentAs(type, null);
        }
        private static object ReadElementValue(XmlReader reader, List<Type> types)
        {
            Type matchedType = types.FirstOrDefault(x => x.IsPrimitive || x == typeof(string) ? String.Equals(x.Name, reader.Name, StringComparison.OrdinalIgnoreCase) : x.Name == reader.Name);
            if (matchedType == null)
                throw new XmlException(types.Count > 1 ? $"Element '{reader.Name}' does not match any of the following:\r\n" + string.Join("\r\n", types.Select(x => x.Name)) :
                    $"Element '{reader.Name}' does not match expected type '{types.FirstOrDefault()?.Name}'");
            return ReadElementValue(reader, matchedType);
        }
        private bool MoveToNextElement(XmlReader reader, string enclosingElement)
        {
            if (reader.NodeType == XmlNodeType.EndElement && reader.Name == enclosingElement)
            {
                reader.ReadEndElement();
                return false;
            }
            reader.Read();
            while (reader.NodeType != XmlNodeType.Element)
            {
                if (reader.NodeType == XmlNodeType.EndElement && reader.Name == enclosingElement)
                {
                    reader.ReadEndElement();
                    return false;
                }
                if (!reader.Read())
                    throw new XmlException("Unexpected end of XML document.");

                if (reader.NodeType == XmlNodeType.Text)
                    throw new XmlException("Unexpected text.");
            }
            return true;
        }
    }
}
