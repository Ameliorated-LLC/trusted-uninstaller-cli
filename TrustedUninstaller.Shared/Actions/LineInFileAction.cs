using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TrustedUninstaller.Shared.Exceptions;
using TrustedUninstaller.Shared.Tasks;
using YamlDotNet.Serialization;

namespace TrustedUninstaller.Shared.Actions
{
    internal enum LineInFileOperation
    {
        Delete = 0,
        Add = 1
    }
    internal class LineInFileAction : ITaskAction
    {
        [YamlMember(Alias = "path")]
        public string RawPath { get; set; }

        [YamlMember(Alias = "line")]
        public string RawLines { get; set; }

        [YamlMember(Alias = "operation")]
        public LineInFileOperation Operation { get; set; } = LineInFileOperation.Delete;
        
        [YamlMember(typeof(string), Alias = "weight")]
        public int ProgressWeight { get; set; } = 1;
        public int GetProgressWeight() => ProgressWeight;

        private bool InProgress { get; set; } = false;
        public void ResetProgress() => InProgress = false;
        
        public string ErrorString() => $"LineInFileAction failed to {Operation.ToString().ToLower()} lines to file '{RawPath}'.";
        
        public UninstallTaskStatus GetStatus()
        {
            if (InProgress)
            {
                return UninstallTaskStatus.InProgress;
            }

            var realPath = this.GetRealPath();
            if (!File.Exists(realPath))
            {
                // If the file doesn't exist it can't contain the lines either, can it?
                return Operation == LineInFileOperation.Delete ?
                    UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
            }
            
            var isDone = !GetMissingLines().Any();

            return isDone ? UninstallTaskStatus.Completed : UninstallTaskStatus.ToDo;
        }

        private IEnumerable<string> GetLines() =>
            RawLines.Split(
                new[] { "\r\n", "\r", "\n" },
                StringSplitOptions.None
            );

        private IEnumerable<string> GetMissingLines()
        {
            var realPath = this.GetRealPath();
            var fileLines = File.ReadAllLines(realPath);
            var targetLines = GetLines();

            return targetLines.Where(line => !fileLines.Contains(line));
        }

        private string GetRealPath()
        {
            return Environment.ExpandEnvironmentVariables(RawPath);
        }

        public async Task<bool> RunTask()
        {
            if (InProgress) throw new TaskInProgressException("Another LineInFile action was called while one was in progress.");
            InProgress = true;
            
            //Wording should be improved here
            Console.WriteLine($"{Operation.ToString().TrimEnd('e')}ing text lines in file '{RawPath}'...");

            var realPath = this.GetRealPath();
            var missingLines = GetMissingLines();
            
            using var sw = File.AppendText(realPath);
            foreach (var missingLine in missingLines)
            {
                await sw.WriteLineAsync(missingLine);
            }

            InProgress = false;
            return true;
        }
    }
}