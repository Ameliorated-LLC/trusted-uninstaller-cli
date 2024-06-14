using System;
using System.DirectoryServices;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using Core;

namespace TrustedUninstaller.Shared.Actions
{
    public class UserAction : Tasks.TaskAction, ITaskAction
    {
        public void RunTaskOnMainThread(Output.OutputWriter output) { throw new NotImplementedException(); }
        [YamlMember(typeof(string), Alias = "name")]
        public string Username { get; set; } = "";
        [YamlMember(typeof(bool), Alias = "admin")]
        public bool IsAdmin { get; set; } = false;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;
        public ErrorAction GetDefaultErrorAction() => Tasks.ErrorAction.Notify;
        public bool GetRetryAllowed() => true;
        
        private bool InProgress { get; set; }
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"UserAction failed to change permissions for user {Username}.";
        
        public UninstallTaskStatus GetStatus(Output.OutputWriter output)
        {
            using var pc = new PrincipalContext(ContextType.Machine);

            var up = UserPrincipal.FindByIdentity(
                pc,
                IdentityType.SamAccountName,
                this.Username);

            var userExists = (up != null);

            if (!IsAdmin || !userExists) return userExists ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            
            var identity = new WindowsIdentity(up.UserPrincipalName);
            var principal = new WindowsPrincipal(identity);

            var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            return isAdmin ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }

        public async Task<bool> RunTask(Output.OutputWriter output)
        {
            if (this.GetStatus(output) != UninstallTaskStatus.ToDo)
            {
                return false;
            }
            
            output.WriteLineSafe("Info", $"Changing permissions for user '{Username}'...");

            return await Task.Run(() =>
            {
                using var pc = new PrincipalContext(ContextType.Machine);

                var up = UserPrincipal.FindByIdentity(
                    pc,
                    IdentityType.SamAccountName,
                    this.Username);

                var userExists = (up != null);
                var ad = new DirectoryEntry("WinNT://" +
                    Environment.MachineName + ",computer");
                if (!userExists)
                {

                    var newUser = ad.Children.Add(this.Username, "user");

                    newUser.Invoke("SetPassword", "user");
                    newUser.Invoke("Put", "Description", "Created by the AME Wizard");
                    newUser.CommitChanges();


                    if (IsAdmin)
                    {
                        var group = ad.Children.Find("Administrators", "group");
                        group.Invoke("Add", newUser.Path);
                        group.CommitChanges();
                    }
                }
                else
                {
                    if (IsAdmin)
                    {
                        var group = ad.Children.Find("Administrators", "group");
                        group.Invoke("Add", up.UserPrincipalName);
                        group.CommitChanges();
                    }
                }
                    

                return true;
            });
        }
    }
}
