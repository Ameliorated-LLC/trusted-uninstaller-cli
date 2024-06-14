using System;

namespace Core.Exceptions
{
    public class UnexpectedException : Exception
    {
        public UnexpectedException() : base() {}
        public UnexpectedException(string message) : base(message) {}
        public UnexpectedException(string message, Exception innerException) : base(message, innerException) {}
    }
}