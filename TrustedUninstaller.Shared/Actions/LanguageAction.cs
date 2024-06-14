using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using Core;
using TrustedUninstaller.Shared.Tasks;

namespace TrustedUninstaller.Shared.Actions
{
    class LanguageAction : Tasks.TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => true;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string Tag { get; set; } = "";
        public string Primary() => "for language " + Tag;
        public bool Display { get; set; } = false;
        
        public string ErrorString() => $"LanguageAction failed to install language {Tag}.";

        [DllImport("intl.cpl", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int IntlUpdateSystemLocale(string LocaleName, int dwFlags);

        public UninstallTaskStatus GetStatus(Output.OutputWriter output) =>
            InputLanguage.InstalledInputLanguages.Cast<InputLanguage>()
                .Any(c => c.Culture.IetfLanguageTag == this.Tag)
                ? UninstallTaskStatus.Completed
                : UninstallTaskStatus.ToDo;

        public async Task<bool> RunTask(Output.OutputWriter output)
        {
            if (GetStatus(output) != UninstallTaskStatus.ToDo)
            {
                return false;
            }

            if (this.Display)
            {
                // Reversed from the Set-WinSystemLocale cmdlet...
                // TODO: Figure out the return value lol
                IntlUpdateSystemLocale(this.Tag, 2);
            }

            // TODO: Installing languages is AIDS
            return false;
        }
    }
}
