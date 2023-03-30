using System;

namespace TrustedUninstaller.Shared.Exceptions
{
    public class InvalidRegistryEntryException : Exception
    {
        public InvalidRegistryEntryException() { }
        public InvalidRegistryEntryException(string message) : base(message) { }
        public InvalidRegistryEntryException(string message, Exception inner) : base(message, inner) { }
    }
}
