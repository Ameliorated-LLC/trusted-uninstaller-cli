using System;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.Shared.Exceptions
{
    public class ErrorHandlingException : Exception
    {
        public ErrorHandlingException(TaskAction.ExitCodeAction action, string message) => (Action, Message) = (action, message);
        public TaskAction.ExitCodeAction Action { get; set; }
        public new string Message { get; set; }
    }
}
