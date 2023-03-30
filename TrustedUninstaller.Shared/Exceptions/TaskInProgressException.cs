using System;

namespace TrustedUninstaller.Shared.Exceptions
{
    public class TaskInProgressException : Exception
    {
        public TaskInProgressException() {}
        public TaskInProgressException(string message) : base(message) {}
        public TaskInProgressException(string message, Exception inner) : base(message, inner) {}
    }
}
