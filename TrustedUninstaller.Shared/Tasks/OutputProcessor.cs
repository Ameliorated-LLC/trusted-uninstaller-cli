using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Core;
using JetBrains.Annotations;
using TrustedUninstaller.Shared.Actions;
using static Core.Output;

namespace TrustedUninstaller.Shared.Tasks
{
    public abstract class TaskActionWithOutputProcessor : Tasks.TaskAction
    {
        protected static bool ExeRunning(string name, int id)
        {
            try
            {
                return Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name)).Any(x => x.Id == id);
            }
            catch (Exception)
            {
                return false;
            }
        }
        
        protected class OutputHandler : IDisposable
        {
            [System.Runtime.InteropServices.DllImport("kernel32.dll")]
            static extern uint GetOEMCP();            
            
            private readonly SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
            private readonly OutputWriter writer;
            private readonly string name;
            private readonly Process process;
            private readonly AugmentedProcess.Process augmentedProcess;
            private static readonly Encoding s_outputEncoding = Encoding.GetEncoding((int)GetOEMCP());
            
            public OutputHandler(string name, Process process, [NotNull] OutputWriter writer)
            {
                this.name = name;
                this.writer = writer;
                this.process = process;
                if (!process.StartInfo.RedirectStandardOutput)
                    OutputEndReached.Set();
                if (!process.StartInfo.RedirectStandardError)
                    ErrorEndReached.Set();

                if (process.StartInfo.RedirectStandardOutput)
                {
                    process.StartInfo.StandardOutputEncoding = s_outputEncoding;
                    process.OutputDataReceived += WriteOutputSafe;
                }
                if (process.StartInfo.RedirectStandardError)
                {
                    process.StartInfo.StandardErrorEncoding = s_outputEncoding;
                    process.ErrorDataReceived += WriteErrorSafe;
                }
            }
            public OutputHandler(string name, AugmentedProcess.Process process, [NotNull] OutputWriter writer)
            {
                this.name = name;
                this.writer = writer;
                this.augmentedProcess = process;
                if (!process.StartInfo.RedirectStandardOutput)
                    OutputEndReached.Set();
                if (!process.StartInfo.RedirectStandardError)
                    ErrorEndReached.Set();

                if (process.StartInfo.RedirectStandardOutput)
                {
                    process.StartInfo.StandardOutputEncoding = s_outputEncoding;
                    process.OutputDataReceived += WriteOutputSafe;
                }
                if (process.StartInfo.RedirectStandardError)
                {
                    process.StartInfo.StandardErrorEncoding = s_outputEncoding;
                    process.ErrorDataReceived += WriteErrorSafe;
                }
            }
            public void StartProcess(Privilege privilege = Privilege.TrustedInstaller)
            {
                if (process != null)
                {
                    process.Start();
                    if (process.StartInfo.RedirectStandardOutput)
                        process.BeginOutputReadLine();
                    if (process.StartInfo.RedirectStandardError)
                        process.BeginErrorReadLine();
                } else if (augmentedProcess != null)
                {
                    ProcessPrivilege.StartPrivilegedTask(augmentedProcess, privilege);
                    if (augmentedProcess.StartInfo.RedirectStandardOutput)
                        augmentedProcess.BeginOutputReadLine();
                    if (augmentedProcess.StartInfo.RedirectStandardError)
                        augmentedProcess.BeginErrorReadLine();
                }
            }
            public void CancelReading()
            {
                if (process != null)
                {
                    if (process.StartInfo.RedirectStandardOutput)
                    {
                        process.CancelOutputRead();
                        using (TryLock(5000))
                        {
                            outputTask = outputTask.ContinueWith(_ =>
                            {
                                if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                    lastThree.Last().Stream?.Erase();

                                foreach (var group in progressGroups)
                                    group.Lines.ForEach(x => x.Stream?.Dispose());
                                lastThree.ForEach(x => x.Stream?.Dispose());
                                progressGroups.Clear();
                                lastThree.Clear();

                                OutputEndReached.Set();
                            });
                        }
                    }
                    if (process.StartInfo.RedirectStandardError)
                    {
                        process.CancelErrorRead();
                        using (TryLock(5000))
                        {
                            outputTask = outputTask.ContinueWith(_ =>
                            {
                                if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                    lastThree.Last().Stream?.Erase();

                                foreach (var group in progressGroups)
                                    group.Lines.ForEach(x => x.Stream?.Dispose());
                                lastThree.ForEach(x => x.Stream?.Dispose());
                                progressGroups.Clear();
                                lastThree.Clear();

                                ErrorEndReached.Set();
                            });
                        }
                    }
                } else if (augmentedProcess != null)
                {
                    if (augmentedProcess.StartInfo.RedirectStandardOutput)
                    {
                        augmentedProcess.CancelOutputRead();
                        using (TryLock(5000))
                        {
                            outputTask = outputTask.ContinueWith(_ =>
                            {
                                if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                    lastThree.Last().Stream?.Erase();

                                foreach (var group in progressGroups)
                                    group.Lines.ForEach(x => x.Stream?.Dispose());
                                lastThree.ForEach(x => x.Stream?.Dispose());
                                progressGroups.Clear();
                                lastThree.Clear();

                                OutputEndReached.Set();
                            });
                        }
                    }
                    if (augmentedProcess.StartInfo.RedirectStandardError)
                    {
                        augmentedProcess.CancelErrorRead();
                        using (TryLock(5000))
                        {
                            outputTask = outputTask.ContinueWith(_ =>
                            {
                                if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                    lastThree.Last().Stream?.Erase();

                                foreach (var group in progressGroups)
                                    group.Lines.ForEach(x => x.Stream?.Dispose());
                                lastThree.ForEach(x => x.Stream?.Dispose());
                                progressGroups.Clear();
                                lastThree.Clear();

                                ErrorEndReached.Set();
                            });
                        }
                    }
                }

                if (!OutputEndReached.Wait(2500))
                    Log.EnqueueSafe(LogType.Warning, "Output processing did not finish after cancel.", new SerializableTrace(), writer.LogOptions);
                if (!ErrorEndReached.Wait(2500))
                    Log.EnqueueSafe(LogType.Warning, "Error processing did not finish after cancel.", new SerializableTrace(), writer.LogOptions);
            }

            private IDisposable TryLock(int timout = Timeout.Infinite)
            {
                if (!semaphore.Wait(timout))
                    return null;
                return new Releaser(semaphore);
            }

            public void Dispose()
            {
                bool dispose = true;
                if (!OutputEndReached.Wait(5000))
                {
                    dispose = false;
                    Log.EnqueueSafe(LogType.Warning, "Output processing did not finish.", new SerializableTrace(), writer.LogOptions);
                }
                if (!ErrorEndReached.Wait(5000))
                {
                    dispose = false;
                    Log.EnqueueSafe(LogType.Warning, "Error processing did not finish.", new SerializableTrace(), writer.LogOptions);
                }
                if (dispose)
                {
                    semaphore.Dispose();
                }
            }

            private class Releaser : IDisposable
            {
                private readonly SemaphoreSlim semaphore;

                public Releaser(SemaphoreSlim semaphore) => this.semaphore = semaphore;
                public void Dispose()
                {
                    try
                    {
                        semaphore.Release();
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                }
            }

            private readonly ManualResetEventSlim OutputEndReached = new ManualResetEventSlim(false);
            private readonly ManualResetEventSlim ErrorEndReached = new ManualResetEventSlim(false);

            private readonly List<ProgressLine> lastThree = new List<ProgressLine>();
            private readonly List<ProgressGroup> progressGroups = new List<ProgressGroup>();
            private Task outputTask = Task.CompletedTask;

            private void WriteErrorSafe(object _, object args)
            {
                var text = args is DataReceivedEventArgs ? ((DataReceivedEventArgs)args).Data : ((AugmentedProcess.DataReceivedEventArgs)args).Data;
                if (text == null)
                {
                    if (Monitor.TryEnter(this))
                    {
                        try
                        {
                            OutputEndReached.Wait(5000);
                        }
                        finally
                        {
                            Monitor.Exit(this);
                        }
                    }
                    
                    using (TryLock(5000))
                    {
                        outputTask = outputTask.ContinueWith(_ =>
                        {
                            if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                lastThree.Last().Stream?.Erase();

                            foreach (var group in progressGroups)
                                group.Lines.ForEach(x => x.Stream?.Dispose());
                            lastThree.ForEach(x => x.Stream?.Dispose());
                            progressGroups.Clear();
                            lastThree.Clear();

                            ErrorEndReached.Set();
                        });
                    }
                    return;
                }
                
                using (TryLock(5000))
                    outputTask = outputTask.ContinueWith(_ => Wrap.ExecuteSafe(() => WriteError(text), true));
            }
            private void WriteError([NotNull] string text)
            {
                if (ErrorEndReached.Wait(0))
                {
                    if (!string.IsNullOrWhiteSpace(text))
                        Log.EnqueueSafe(LogType.Warning, $"Unexpected error output received after null:\r\n{text}", new SerializableTrace(), writer.LogOptions);
                    return;
                }

                WriteUnsafe(name + " | Err", text);
            }

            private void WriteOutputSafe(object _, object args)
            {                
                var text = args is DataReceivedEventArgs ? ((DataReceivedEventArgs)args).Data : ((AugmentedProcess.DataReceivedEventArgs)args).Data;
                if (text == null)
                {
                    if (Monitor.TryEnter(this))
                    {
                        try
                        {
                            ErrorEndReached.Wait(5000);
                        }
                        finally
                        {
                            Monitor.Exit(this);
                        }
                    }
                    
                    using (TryLock(5000))
                    {
                        outputTask = outputTask.ContinueWith(_ =>
                        {
                            if (lastThree.Count > 0 && lastThree.Last().Pattern.IsNullOrEmpty)
                                lastThree.Last().Stream?.Erase();

                            foreach (var group in progressGroups)
                                group.Lines.ForEach(x => x.Stream?.Dispose());
                            lastThree.ForEach(x => x.Stream?.Dispose());
                            progressGroups.Clear();
                            lastThree.Clear();

                            OutputEndReached.Set();
                        });
                    }
                    return;
                }
                
                using (TryLock(5000))
                    outputTask = outputTask.ContinueWith(_ => Wrap.ExecuteSafe(() => WriteOutput(text), true));
            }
            private void WriteOutput([NotNull] string text)
            {
                if (OutputEndReached.Wait(0))
                {
                    if (!string.IsNullOrWhiteSpace(text))
                        Log.EnqueueSafe(LogType.Warning, $"Unexpected output received after null:\r\n{text}", new SerializableTrace(), writer.LogOptions);
                    return;
                }

                WriteUnsafe(name + " | Out", text);
            }
            private void WriteUnsafe(string type, [NotNull] string text)
            {
                int index = text.IndexOf('>');
                if (index >= 0)
                {
                    string directory = text.Substring(0, index);
                    if (Directory.Exists(directory))
                        text = text.Substring(index + 1).Trim();
                }
                
                if (text.Length > 512)
                {
                    AddToCycle(null, new ProgressPattern(null));

                    if (progressGroups.Count > 0)
                    {
                        foreach (var group in new List<ProgressGroup>(progressGroups))
                        {
                            if (group.Cycles >= group.Lines.Count - 1)
                            {
                                progressGroups.Remove(group);
                                group.Lines.ForEach(x =>
                                {
                                    if (!progressGroups.Any(y => y.Lines.Contains(x)) && !lastThree.Contains(x))
                                    {
                                        x.Stream?.Dispose();
                                        x.Stream = null;
                                    }
                                });
                                continue;
                            }

                            group.Cycles++;
                        }
                    }

                    writer.WriteLineSafe(type, text);
                    return;
                }

                var pattern = new ProgressPattern(text);
                AddToCycle(null, pattern);
                ProgressGroup handledGroup = null;
                ProgressGroup addedGroup = null;

                if (!string.IsNullOrWhiteSpace(text) && pattern.HasProgressElements)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        if (j > 0 && (lastThree.Count < j || !lastThree[j - 1].IsProgress))
                            continue;

                        foreach (var group in new List<ProgressGroup>(progressGroups))
                        {
                            if (group.Cycles == 2 - j && ProgressPattern.SequenceEqual(lastThree, j, group.Lines, j))
                            {
                                bool nullStream = false;
                                for (var i = j; i < lastThree.Count; i++)
                                {
                                    if (i < j)
                                        continue;
                                    if (group.Lines[i].Stream == null)
                                    {
                                        nullStream = true;
                                        break;
                                    }

                                    if (group.Lines[i].Stream.Flushed)
                                    {
                                        group.Lines[i].Pattern = lastThree[i].Pattern;
                                        group.Lines[i].Stream.WriteSafe(lastThree[i].Pattern.GetString());
                                    }
                                    else
                                    {
                                        group.Lines[i].Stream.WriteSafe(lastThree[i].Pattern.GetString(group.Lines[i].Pattern));
                                    }

                                    lastThree[i].IsProgress = group.Lines[i].IsProgress;

                                    if (!ReferenceEquals(lastThree[i].Pattern, pattern) && !group.Lines.Any(x => x == lastThree[i]))
                                    {
                                        progressGroups.RemoveAll(x => x.Lines.Any(y => y == lastThree[i]));
                                        lastThree[i].Stream?.Erase();
                                        lastThree[i].Stream?.Dispose();
                                        lastThree[i].Stream = null;
                                        group.Cycles--;
                                    }
                                }
                                if (nullStream)
                                    continue;

                                handledGroup = group;
                                break;
                            }
                        }
                    }

                    if (handledGroup == null)
                    {
                        lastThree.Last().IsProgress = true;
                        progressGroups.Add(new ProgressGroup(lastThree));
                        addedGroup = progressGroups.Last();
                    }
                }

                if (progressGroups.Count > 0)
                {
                    foreach (var group in new List<ProgressGroup>(progressGroups.Where(x => x != handledGroup && x != addedGroup)))
                    {
                        if (group.Cycles >= group.Lines.Count - 1 || handledGroup != null)
                        {
                            progressGroups.Remove(group);
                            group.Lines.ForEach(x =>
                            {
                                if (!progressGroups.Any(y => y.Lines.Contains(x)) && !lastThree.Contains(x))
                                {
                                    x.Stream?.Dispose();
                                    x.Stream = null;
                                }
                            });
                            continue;
                        }

                        group.Cycles++;
                    }
                }
                if (handledGroup != null)
                    return;

                lastThree.Last().Stream = new OutputWriter.LineStream(writer, type);
                lastThree.Last().Stream.WriteSafe(text);
            }

            private void AddToCycle(OutputWriter.LineStream stream, ProgressPattern pattern)
            {
                if (lastThree.Count == 3)
                {
                    if (lastThree[0].Stream != null && !progressGroups.Any(x => x.Lines.Any(y => y.Stream == lastThree[0].Stream)))
                    {
                        lastThree[0].Stream.Dispose();
                        lastThree[0].Stream = null;
                    }
                    lastThree.RemoveAt(0);
                }
                lastThree.Add(new ProgressLine(stream, pattern));

                while (lastThree.Count < 3)
                {
                    lastThree.Insert(0, new ProgressLine(null, new ProgressPattern(string.Empty)));
                }
            }
        }

        private class ProgressLine
        {
            public OutputWriter.LineStream Stream;
            public ProgressPattern Pattern;
            public bool IsProgress = false;
            public ProgressLine(OutputWriter.LineStream stream, ProgressPattern pattern) => (Stream, Pattern) = (stream, pattern);
        }

        private class ProgressGroup
        {
            public readonly List<ProgressLine> Lines;
            public int Cycles;
            public ProgressGroup(List<ProgressLine> lines) => Lines = new List<ProgressLine>(lines);
        }

        private class ProgressPattern
        {
            private ProgressPattern() { }

            private static readonly string[] DefiniteProceedingIndicators =
            {
                "%",
            };

            // Must be sorted by length
            private static readonly string[] ProceedingIndicators =
            {
                "KiB/s",
                "MiB/s",
                "GiB/s",
                "TiB/s",

                ")...",

                "kB/s",
                "mB/s",
                "gB/s",
                "tB/s",

                "mins",
                "secs",

                "KiBs",
                "MiBs",
                "GiBs",
                "TiBs",

                "KB/s",
                "MB/s",
                "GB/s",
                "TB/s",
                "B/s",

                "KiB",
                "MiB",
                "GiB",
                "TiB",

                "min",
                "sec",
                "...",

                "KBs",
                "MBs",
                "GBs",
                "TBs",

                "KB",
                "MB",
                "GB",
                "TB",

                "ms",
                "m",
                "s",

                "|",
                "%",
            };

            private static readonly string[] DefinitePreceedingIndicators =
                { };

            // Must be sorted by length
            private static readonly string[] PreceedingIndicators =
            {
                "|",
            };

            private static readonly char[] ParsableChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', };
            private static readonly char[] ProgressChars = { '>', '#', '=', '*', '.', '\u2593', '\u25a0', '\u25a0', '\u258f', '\u258e', '\u258d', '\u258c', '\u258b', '\u258a', '\u2589', '\u2588' };
            private static readonly char[] ReplaceableChars = { '-', ' ', '\u2592', '\u25a2', '\u25a1' };

            private static readonly char[] PreceedingWrapChars = { ' ', '\n', '\r', '(', '[', ':' };
            private static readonly char[] ProceedingWrapChars = { ' ', '\n', '\r', ')', ']', ':' };

            private class ProgressItem
            {
                public bool IsParsable { get; private set; }
                public string Text { get; private set; }
                public int Index { get; set; }
                [CanBeNull] public string ProceedingIndicator { get; private set; }
                public ProgressItem(bool isParsable, string text, int index, [CanBeNull] string proceedingIndicator) => (IsParsable, Text, Index, ProceedingIndicator) = (isParsable, text, index, proceedingIndicator);

                public static bool SequenceEqual([NotNull] List<ProgressItem> first, [NotNull] List<ProgressItem> second)
                {
                    if (first.Count != second.Count)
                        return false;

                    for (var i = 0; i < first.Count; i++)
                    {

                        if (first[i].IsParsable != second[i].IsParsable)
                            return false;
                        if (first[i].Index != second[i].Index)
                            return false;
                    }

                    return true;
                }
            }

            private static readonly char[] OutOfSeparators = { '/', '-' };

            private List<char> ProgressExcludedChars { get; set; } = new List<char>();
            private List<ProgressItem> ProgressItems { get; set; } = new List<ProgressItem>();

            public bool HasProgressElements => ProgressItems.Count > 0;

            public readonly bool IsNullOrEmpty = false;

            public ProgressPattern(string text)
            {
                if (string.IsNullOrEmpty(text))
                {
                    IsNullOrEmpty = true;
                    return;
                }

                int i = 0;
                while (i < text.Length)
                {
                    var startItemCount = ProgressItems.Count;

                    if (ParsableChars.Contains(text[i]))
                    {
                        int parseIndex = i;
                        bool separatorFound = false;
                        while (parseIndex < text.Length && (ParsableChars.Contains(text[parseIndex]) || (text.Length > parseIndex + 1 && ParsableChars.Contains(text[parseIndex + 1]) && (!separatorFound && (text[parseIndex] == '.' || text[parseIndex] == ',')))))
                        {
                            if (text[parseIndex] == '.' || text[parseIndex] == ',')
                                separatorFound = true;
                            parseIndex++;
                        }

                        var proceeding = text.Substring(parseIndex, text.Length - parseIndex);
                        var preceeding = text.Substring(0, i);

                        string proceedingIndicator = null;

                        // Account for expressions like 100MB/200MB or 100/200
                        int outOfIndex = 0;
                        if (text.Length > parseIndex + 1 && (OutOfSeparators.Contains(text[parseIndex]) || ((proceedingIndicator = ProceedingIndicators.FirstOrDefault(x => text.Length > parseIndex + x.Length + 1 && proceeding.StartsWith(x))) != null && OutOfSeparators.Contains(text[parseIndex + proceedingIndicator.Length]))))
                        {
                            outOfIndex = proceedingIndicator == null ? parseIndex + 1 : parseIndex + proceedingIndicator.Length + 1;
                            if (ParsableChars.Contains(text[outOfIndex]))
                            {
                                for (; outOfIndex < text.Length && (ParsableChars.Contains(text[outOfIndex]) || (text.Length > outOfIndex + 1 && ParsableChars.Contains(text[outOfIndex + 1]) && (text[outOfIndex] == '.' || text[outOfIndex] == ','))); outOfIndex++) { }
                                var outOfProceeding = text.Substring(outOfIndex, text.Length - outOfIndex);
                                string outOfProceedingIndicator;

                                if ((outOfProceedingIndicator = DefiniteProceedingIndicators.FirstOrDefault(x => outOfProceeding.StartsWith(x))) != null)
                                    ProgressItems.Add(new ProgressItem(true, text.Substring(i, parseIndex - i).Replace(',', '.'), ProgressExcludedChars.Count, proceedingIndicator));
                                else if (outOfProceeding.Length == 0 || ProceedingWrapChars.Contains(outOfProceeding[0]) || (outOfProceedingIndicator = ProceedingIndicators.FirstOrDefault(x => outOfProceeding.StartsWith(x) && (outOfProceeding.Length == x.Length || ProceedingWrapChars.Contains(outOfProceeding[x.Length])))) != null)
                                    ProgressItems.Add(new ProgressItem(true, text.Substring(i, parseIndex - i).Replace(',', '.'), ProgressExcludedChars.Count, proceedingIndicator));

                                if (outOfProceeding != null)
                                    outOfIndex += outOfProceedingIndicator?.Length ?? 0;
                            }
                        }
                        else if ((proceedingIndicator = DefiniteProceedingIndicators.FirstOrDefault(x => proceeding.StartsWith(x))) != null)
                            ProgressItems.Add(new ProgressItem(true, text.Substring(i, parseIndex - i).Replace(',', '.'), ProgressExcludedChars.Count, proceedingIndicator));
                        else if (DefinitePreceedingIndicators.Any(x => preceeding.EndsWith(x)))
                            ProgressItems.Add(new ProgressItem(true, text.Substring(i, parseIndex - i).Replace(',', '.'), ProgressExcludedChars.Count, null));
                        else if ((proceeding.Length == 0 || ProceedingWrapChars.Contains(proceeding[0]) || (proceedingIndicator = ProceedingIndicators.FirstOrDefault(x => proceeding.StartsWith(x) && (proceeding.Length == x.Length || ProceedingWrapChars.Contains(proceeding[x.Length])))) != null) && (preceeding.Length == 0 || PreceedingWrapChars.Contains(preceeding.Last()) || PreceedingIndicators.Any(x => preceeding.EndsWith(x) && (preceeding.Length == x.Length || PreceedingWrapChars.Contains(preceeding[(preceeding.Length - 1) - x.Length])))))
                            ProgressItems.Add(new ProgressItem(true, text.Substring(i, parseIndex - i).Replace(',', '.'), ProgressExcludedChars.Count, proceedingIndicator));


                        if (startItemCount != ProgressItems.Count)
                        {
                            if (proceedingIndicator != null)
                            {
                                foreach (var proceedingChar in proceedingIndicator)
                                {
                                    ProgressExcludedChars.Add(proceedingChar);
                                    parseIndex++;
                                }
                            }
                            while (parseIndex < outOfIndex)
                            {
                                ProgressExcludedChars.Add(text[parseIndex]);
                                parseIndex++;
                            }
                            i = parseIndex;
                            continue;
                        }
                        else
                        {
                            if (i == parseIndex)
                                ProgressExcludedChars.Add(text[i]);
                            else
                            {
                                for (; i < parseIndex && i < text.Length; i++)
                                {
                                    ProgressExcludedChars.Add(text[i]);
                                }
                            }
                            continue;
                        }
                    }

                    if (ProgressChars.Contains(text[i]))
                    {
                        int parseIndex = i;
                        bool replaceableFound = false;
                        bool continueLoop = false;
                        while (parseIndex < text.Length)
                        {
                            if (ReplaceableChars.Contains(text[parseIndex]))
                            {
                                replaceableFound = true;
                                parseIndex++;
                                continue;
                            }
                            if (ProgressChars.Contains(text[parseIndex]))
                            {
                                if (replaceableFound)
                                    break;
                                parseIndex++;
                                continue;
                            }

                            if (ParsableChars.Contains(text[parseIndex]))
                            {
                                continueLoop = true;

                                var internalPreceeding = text.Substring(0, i);
                                if (!(internalPreceeding.Length == 0 || PreceedingWrapChars.Contains(internalPreceeding.Last()) || PreceedingIndicators.Any(x => internalPreceeding.EndsWith(x) && (internalPreceeding.Length == x.Length || PreceedingWrapChars.Contains(internalPreceeding[(internalPreceeding.Length - 1) - x.Length])))))
                                    break;

                                var progressCharEnd = parseIndex;
                                bool separatorFound = false;
                                while (parseIndex < text.Length && (ParsableChars.Contains(text[parseIndex]) || (text.Length > parseIndex + 1 && ParsableChars.Contains(text[parseIndex + 1]) && (!separatorFound && (text[parseIndex] == '.' || text[parseIndex] == ',')))))
                                {
                                    if (text[parseIndex] == '.' || text[parseIndex] == ',')
                                        separatorFound = true;
                                    parseIndex++;
                                }

                                var parsableProceeding = text.Substring(parseIndex, text.Length - parseIndex);

                                string parsableProceedingIndicator = null;

                                // Account for expressions like 100MB/200MB or 100/200
                                int outOfIndex = 0;
                                if (text.Length > parseIndex + 1 && (OutOfSeparators.Contains(text[parseIndex]) || ((parsableProceedingIndicator = ProceedingIndicators.FirstOrDefault(x => text.Length > parseIndex + x.Length + 1 && parsableProceeding.StartsWith(x))) != null && OutOfSeparators.Contains(text[parseIndex + parsableProceedingIndicator.Length]))))
                                {
                                    outOfIndex = parsableProceedingIndicator == null ? parseIndex + 1 : parseIndex + parsableProceedingIndicator.Length + 1;
                                    if (ParsableChars.Contains(text[outOfIndex]))
                                    {
                                        for (; outOfIndex < text.Length && (ParsableChars.Contains(text[outOfIndex]) || (text.Length > outOfIndex + 1 && ParsableChars.Contains(text[outOfIndex + 1]) && (text[outOfIndex] == '.' || text[outOfIndex] == ','))); outOfIndex++) { }
                                        var outOfProceeding = text.Substring(outOfIndex, text.Length - outOfIndex);
                                        string outOfProceedingIndicator;

                                        if ((outOfProceedingIndicator = DefiniteProceedingIndicators.FirstOrDefault(x => outOfProceeding.StartsWith(x))) != null)
                                            ProgressItems.Add(new ProgressItem(true, text.Substring(progressCharEnd, parseIndex - progressCharEnd).Replace(',', '.'), ProgressExcludedChars.Count, parsableProceedingIndicator));
                                        else if (outOfProceeding.Length == 0 || (ProgressChars.Contains(outOfProceeding[0]) || ReplaceableChars.Contains(outOfProceeding[0]) || ProceedingWrapChars.Contains(outOfProceeding[0])) || (outOfProceedingIndicator = ProceedingIndicators.FirstOrDefault(x => outOfProceeding.StartsWith(x) && (outOfProceeding.Length == x.Length || ProgressChars.Contains(outOfProceeding[x.Length]) || ReplaceableChars.Contains(outOfProceeding[x.Length]) || ProceedingWrapChars.Contains(outOfProceeding[x.Length])))) != null)
                                            ProgressItems.Add(new ProgressItem(true, text.Substring(progressCharEnd, parseIndex - progressCharEnd).Replace(',', '.'), ProgressExcludedChars.Count, parsableProceedingIndicator));

                                        if (outOfProceeding != null)
                                            outOfIndex += outOfProceedingIndicator?.Length ?? 0;
                                    }
                                }
                                else if ((parsableProceedingIndicator = DefiniteProceedingIndicators.FirstOrDefault(x => parsableProceeding.StartsWith(x))) != null)
                                    ProgressItems.Add(new ProgressItem(true, text.Substring(progressCharEnd, parseIndex - progressCharEnd).Replace(',', '.'), ProgressExcludedChars.Count, parsableProceedingIndicator));
                                else if (parsableProceeding.Length == 0 || ProceedingWrapChars.Contains(parsableProceeding[0]) || (parsableProceedingIndicator = ProceedingIndicators.FirstOrDefault(x => parsableProceeding.StartsWith(x) && (parsableProceeding.Length == x.Length || ProgressChars.Contains(parsableProceeding[x.Length]) || ReplaceableChars.Contains(parsableProceeding[x.Length]) || ProceedingWrapChars.Contains(parsableProceeding[x.Length])))) != null)
                                    ProgressItems.Add(new ProgressItem(true, text.Substring(progressCharEnd, parseIndex - progressCharEnd).Replace(',', '.'), ProgressExcludedChars.Count, parsableProceedingIndicator));

                                if (startItemCount != ProgressItems.Count)
                                {
                                    ProgressItems.Insert(ProgressItems.Count - 1, new ProgressItem(false, text.Substring(i, progressCharEnd - i), ProgressExcludedChars.Count, null));
                                    startItemCount = ProgressItems.Count;
                                    if (parsableProceedingIndicator != null)
                                    {
                                        foreach (var proceedingChar in parsableProceedingIndicator)
                                        {
                                            ProgressExcludedChars.Add(proceedingChar);
                                            parseIndex++;
                                        }
                                    }
                                    while (parseIndex < outOfIndex)
                                    {
                                        ProgressExcludedChars.Add(text[parseIndex]);
                                        parseIndex++;
                                    }
                                    i = parseIndex;

                                    bool secondPartReplaceableFound = false;
                                    while (parseIndex < text.Length)
                                    {
                                        if (ReplaceableChars.Contains(text[parseIndex]))
                                        {
                                            secondPartReplaceableFound = true;
                                            parseIndex++;
                                            continue;
                                        }
                                        if (ProgressChars.Contains(text[parseIndex]))
                                        {
                                            if (secondPartReplaceableFound)
                                                break;
                                            parseIndex++;
                                            continue;
                                        }
                                        break;
                                    }
                                    var secondPartProceeding = text.Substring(parseIndex, text.Length - parseIndex);
                                    string secondPartProceedingIndicator = null;
                                    if ((secondPartProceeding.Length == 0 || ProceedingWrapChars.Contains(secondPartProceeding[0]) || text[parseIndex - 1] == ' ' || (secondPartProceedingIndicator = ProceedingIndicators.FirstOrDefault(x => secondPartProceeding.StartsWith(x) && (secondPartProceeding.Length == x.Length || ProceedingWrapChars.Contains(secondPartProceeding[x.Length])))) != null))
                                    {
                                        var value = text.Substring(i, parseIndex - i);
                                        ProgressItems.Add(new ProgressItem(false, value, ProgressExcludedChars.Count, secondPartProceedingIndicator));
                                    }

                                    if (startItemCount != ProgressItems.Count)
                                    {
                                        i = parseIndex;
                                    }
                                }
                            }

                            break;
                        }
                        if (continueLoop)
                        {
                            if (startItemCount == ProgressItems.Count)
                            {
                                if (i == parseIndex)
                                    ProgressExcludedChars.Add(text[i]);
                                else
                                {
                                    for (; i < parseIndex && i < text.Length; i++)
                                    {
                                        ProgressExcludedChars.Add(text[i]);
                                    }
                                }
                            }
                            continue;
                        }

                        var proceeding = text.Substring(parseIndex, text.Length - parseIndex);
                        var preceeding = text.Substring(0, i);

                        string proceedingIndicator = null;
                        if ((proceeding.Length == 0 || ProceedingWrapChars.Contains(proceeding[0]) || (proceedingIndicator = ProceedingIndicators.FirstOrDefault(x => proceeding.StartsWith(x) && (proceeding.Length == x.Length || ProceedingWrapChars.Contains(proceeding[x.Length])))) != null) && (preceeding.Length == 0 || PreceedingWrapChars.Contains(preceeding.Last()) || PreceedingIndicators.Any(x => preceeding.EndsWith(x) && (preceeding.Length == x.Length || PreceedingWrapChars.Contains(preceeding[(preceeding.Length - 1) - x.Length])))))
                        {
                            var value = text.Substring(i, parseIndex - i);

                            ProgressItems.Add(new ProgressItem(false, value, ProgressExcludedChars.Count, proceedingIndicator));
                        }

                        if (startItemCount != ProgressItems.Count)
                        {
                            if (proceedingIndicator != null)
                            {
                                foreach (var proceedingChar in proceedingIndicator)
                                {
                                    ProgressExcludedChars.Add(proceedingChar);
                                    parseIndex++;
                                }
                            }
                            i = parseIndex;
                            continue;
                        }
                        else
                        {
                            if (i == parseIndex)
                                ProgressExcludedChars.Add(text[i]);
                            else
                            {
                                for (; i < parseIndex && i < text.Length; i++)
                                {
                                    ProgressExcludedChars.Add(text[i]);
                                }
                            }
                            continue;
                        }
                    }

                    ProgressExcludedChars.Add(text[i]);
                    i++;
                }
            }

            private readonly ConcurrentDictionary<ProgressPattern, ProgressPattern> _matches = new ConcurrentDictionary<ProgressPattern, ProgressPattern>();

            public bool Compare([NotNull] ProgressPattern pattern)
            {
                if (_matches.TryGetValue(pattern, out _))
                    return true;
                if (pattern.IsNullOrEmpty && IsNullOrEmpty)
                {
                    _matches.TryAdd(pattern, pattern);
                    return true;
                }
                if (pattern.ProgressItems.Count(x => x.IsParsable) != ProgressItems.Count(x => x.IsParsable))
                    return false;
                if (pattern.ProgressExcludedChars.SequenceEqual(ProgressExcludedChars))
                {
                    if (ProgressItem.SequenceEqual(pattern.ProgressItems, ProgressItems))
                    {
                        _matches.TryAdd(pattern, pattern);
                        return true;
                    }
                }

                int patternIndex = 0;
                int thisIndex = 0;

                var result = new ProgressPattern();
                foreach (var patternItem in pattern.ProgressItems)
                {
                    result.ProgressItems.Add(new ProgressItem(patternItem.IsParsable, patternItem.Text, patternItem.Index, patternItem.ProceedingIndicator));
                }

                while (true)
                {
                    while (patternIndex <= pattern.ProgressExcludedChars.Count && thisIndex <= this.ProgressExcludedChars.Count)
                    {
                        ProgressItem item;
                        if (thisIndex != this.ProgressExcludedChars.Count && ReplaceableChars.Contains(this.ProgressExcludedChars[thisIndex]) && (item = pattern.ProgressItems.FirstOrDefault(x => x.Index == patternIndex && !x.IsParsable)) != null)
                        {
                            var upper = thisIndex + item.Text.Length;
                            if (upper > this.ProgressExcludedChars.Count)
                                return false;

                            var originalIndex = thisIndex;
                            while (thisIndex < this.ProgressExcludedChars.Count && ReplaceableChars.Contains(this.ProgressExcludedChars[thisIndex]))
                            {
                                thisIndex++;
                            }

                            var i = this.ProgressItems.IndexOf(item);
                            result.ProgressItems.Insert(i, new ProgressItem(false, item.Text, item.Index, item.ProceedingIndicator));
                            for (i++; i < result.ProgressItems.Count; i++)
                                result.ProgressItems[i].Index -= thisIndex - originalIndex;
                        }
                        else if (patternIndex != pattern.ProgressExcludedChars.Count && ReplaceableChars.Contains(pattern.ProgressExcludedChars[patternIndex]) && (item = this.ProgressItems.FirstOrDefault(x => x.Index == thisIndex && !x.IsParsable)) != null)
                        {
                            var upper = patternIndex + item.Text.Length;
                            if (upper > pattern.ProgressExcludedChars.Count)
                                return false;

                            var originalIndex = patternIndex;
                            while (patternIndex < pattern.ProgressExcludedChars.Count && ReplaceableChars.Contains(pattern.ProgressExcludedChars[patternIndex]))
                            {
                                patternIndex++;
                            }

                            var i = this.ProgressItems.IndexOf(item);
                            result.ProgressItems.Insert(i, new ProgressItem(false, item.Text, item.Index, item.ProceedingIndicator));
                            for (i++; i < result.ProgressItems.Count; i++)
                                result.ProgressItems[i].Index -= patternIndex - originalIndex;
                        }

                        if (patternIndex == pattern.ProgressExcludedChars.Count || thisIndex == this.ProgressExcludedChars.Count)
                            break;

                        bool matches = pattern.ProgressExcludedChars[patternIndex] == this.ProgressExcludedChars[thisIndex];
                        if (!matches)
                            return false;

                        patternIndex++;
                        thisIndex++;
                    }

                    if (!ProgressItem.SequenceEqual(result.ProgressItems, this.ProgressItems))
                        return false;
                    if (patternIndex == pattern.ProgressExcludedChars.Count && thisIndex == this.ProgressExcludedChars.Count)
                    {
                        _matches.TryAdd(pattern, result);
                        return true;
                    }
                    return false;
                }
            }

            public static bool SequenceEqual([NotNull] List<ProgressPattern> first, int skip1, [NotNull] List<ProgressPattern> second, int skip2)
            {
                if (first.Count - skip1 != second.Count - skip2 || first.Count - skip1 <= 0)
                    return false;

                int i1,
                    i2;
                for (i1 = skip1, i2 = skip2; i1 < first.Count - skip1 && i2 < second.Count - skip2; i1++, i2++)
                {
                    if (!first[i1].Compare(second[i2]))
                        return false;
                }

                return true;
            }

            public static bool SequenceEqual([NotNull] List<ProgressLine> first, int skip1, [NotNull] List<ProgressLine> second, int skip2)
            {
                if (first.Count - skip1 != second.Count - skip2 || first.Count - skip1 <= 0)
                    return false;

                int i1,
                    i2;
                for (i1 = skip1, i2 = skip2; i1 < first.Count && i2 < second.Count; i1++, i2++)
                {
                    if (!first[i1].Pattern.Compare(second[i2].Pattern))
                        return false;
                }
                return true;
            }

            public string GetString(ProgressPattern comparison)
            {
                if (!_matches.TryGetValue(comparison, out var match))
                    throw new InvalidOperationException("Compare must be called first.");

                StringBuilder builder = new StringBuilder();

                int lastIndex = 0;
                foreach (var progressItem in ProgressItems)
                {
                    for (var i = lastIndex; i < progressItem.Index && i < ProgressExcludedChars.Count; i++)
                    {
                        builder.Append(ProgressExcludedChars[i]);
                    }

                    var matchedItem = match.ProgressItems.FirstOrDefault(x => x.Index == progressItem.Index && x.IsParsable && progressItem.IsParsable);
                    if (matchedItem != null && matchedItem.Text != progressItem.Text)
                        builder.Append(matchedItem.Text + (matchedItem.ProceedingIndicator == "%" ? matchedItem.ProceedingIndicator : matchedItem.ProceedingIndicator == progressItem.ProceedingIndicator ? null : matchedItem.ProceedingIndicator) + " --> ");
                    builder.Append(progressItem.Text);
                    lastIndex = progressItem.Index;
                }
                for (var i = lastIndex; i < ProgressExcludedChars.Count; i++)
                {
                    builder.Append(ProgressExcludedChars[i]);
                }

                return builder.ToString();
            }

            public string GetString()
            {
                StringBuilder builder = new StringBuilder();

                int lastIndex = 0;
                foreach (var progressItem in ProgressItems)
                {
                    for (var i = lastIndex; i < progressItem.Index && i < ProgressExcludedChars.Count; i++)
                    {
                        builder.Append(ProgressExcludedChars[i]);
                    }

                    builder.Append(progressItem.Text);
                    lastIndex = progressItem.Index;
                }
                for (var i = lastIndex; i < ProgressExcludedChars.Count; i++)
                {
                    builder.Append(ProgressExcludedChars[i]);
                }

                return builder.ToString();
            }
        }
    }
}
