using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Core.Miscellaneous;
using Core.Exceptions;
using JetBrains.Annotations;
using YamlDotNet.Serialization;

namespace Core
{
    public static class Output
    {
        private static readonly IdManager _outputIdManager = new IdManager();

        #region Public methods

        public static void WriteAll([NotNull] string type, [CanBeNull] string text)
        {
            foreach (var writer in _writers.Keys)
            {
                writer.WriteLineSafe(type, text);
            }
        }

        public static void FlushAll()
        {
            foreach (var writer in _writers.Keys)
            {
                if (_writers.TryGetValue(writer, out _))
                    writer.FlushSafe();
            }
        }

        #endregion

        public static string[] SplitByLine(this string text, StringSplitOptions options = StringSplitOptions.None)
        {
            return text.Split(new[]
                { "\r\n", "\n" }, options);
        }
        public static IEnumerable<string> SplitByLength(this string str, int maxLength) {
            int index = 0;
            while(index + maxLength < str.Length) {
                yield return str.Substring(index, maxLength);
                index += maxLength;
            }

            yield return str.Substring(index);
        }

        #region Definitions

        private static ConcurrentDictionary<string, WriterLockPair> _locks = new ConcurrentDictionary<string, WriterLockPair>();
        private static readonly ConcurrentDictionary<OutputWriter, byte> _writers = new ConcurrentDictionary<OutputWriter, byte>();

        private struct WriterLockPair
        {
            public List<OutputWriter> Writers;
            public ConcurrentDictionary<OutputWriter.LineStream, byte> LineStreams;
            public object Lock;
            public object BufferLock;
        }

        public class OutputWriter : IDisposable
        {
            public static readonly OutputWriter Null = new OutputWriter();
            public short ID { get; }
            public string Name { get; }
            [NotNull] public Log.LogOptions LogOptions { get; } = new Log.LogOptions();
            public DateTime StartTimeUtc { get; }
            public string OutputFile { get; private set; }
            
            private string _bufferFile { get; }
            internal long _flushStart = -1;
            internal long _flushEnd = -1;
            private Guid guid = Guid.NewGuid();
            private OutputWriter() {}
            public OutputWriter([NotNull] string name, [NotNull] string outputFile, string logFile = Log.GlobalLog)
            {
                Name = name;
                ID = _outputIdManager.GenerateId();
                StartTimeUtc = DateTime.UtcNow;
                
                LogOptions.LogFile = logFile;
                LogOptions.OutputWriter = this;

                OutputFile = Path.GetFullPath(Environment.ExpandEnvironmentVariables(outputFile));

                var directory = Path.GetDirectoryName(OutputFile);
                var bufferFileName = Path.GetFileNameWithoutExtension(OutputFile) + "Buffer.txt";

                _bufferFile = Path.Combine(directory!, bufferFileName);

                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory!);

                if (_locks.TryGetValue(OutputFile, out var lockPair))
                    lockPair.Writers.Add(this);
                else
                    _locks.TryAdd(outputFile, new WriterLockPair() { Writers = new List<OutputWriter>() { this }, Lock = new object(), BufferLock = new object(), LineStreams = new ConcurrentDictionary<LineStream, byte>() });

                _writers.TryAdd(this, default);
            }

            public void WriteLineSafe([NotNull] string type, [CanBeNull] string text)
            {
                if (OutputFile == null)
                    return;

                WriteBufferSafe(type, text);
            }
            public void WriteLineRawSafe([CanBeNull] string text)
            {
                if (OutputFile == null)
                    return;

                WriteBufferSafe(null, text, true);
            }
            public void FlushSafe()
            {
                if (OutputFile == null)
                    return;
                
                var exception = Wrap.ExecuteSafe(() =>
                {
                    var lockPair = _locks[OutputFile];

                    lock (lockPair.Lock)
                    {
                        bool writeHeader = File.Exists(OutputFile);
                        using (FileStream fileStream = new FileStream(OutputFile, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                        {
                            long totalCopiedBytes = 0;
                            
                            if (_flushStart > -1 && _flushEnd > -1)
                            {
                                if (fileStream.Length == _flushEnd)
                                {
                                    totalCopiedBytes = -1;
                                    writeHeader = false;
                                }
                                else
                                {
                                    fileStream.Seek(0, SeekOrigin.End);

                                    long bytesToCopy = _flushEnd - _flushStart;

                                    long currentReadPosition = _flushStart;
                                    long currentWritePosition = fileStream.Position;

                                    int bufferSize = 4096;
                                    byte[] buffer = new byte[bufferSize];
                                    
                                    while (bytesToCopy > 0)
                                    {
                                        fileStream.Seek(currentReadPosition, SeekOrigin.Begin);
                                        int bytesToRead = (int)Math.Min(bufferSize, bytesToCopy);
                                        int bytesRead = fileStream.Read(buffer, 0, bytesToRead);
                                        if (bytesRead == 0)
                                            break;

                                        fileStream.Seek(currentWritePosition, SeekOrigin.Begin);
                                        fileStream.Write(buffer, 0, bytesRead);

                                        bytesToCopy -= bytesRead;
                                        totalCopiedBytes += bytesRead;
                                        currentReadPosition += bytesRead;
                                        currentWritePosition += bytesRead;
                                    }

                                    if (totalCopiedBytes != 0)
                                        writeHeader = false;

                                    currentReadPosition = _flushStart + totalCopiedBytes;
                                    currentWritePosition = _flushStart;

                                    while (true)
                                    {
                                        fileStream.Seek(currentReadPosition, SeekOrigin.Begin);
                                        int bytesRead = fileStream.Read(buffer, 0, bufferSize);
                                        if (bytesRead == 0)
                                            break;

                                        fileStream.Seek(currentWritePosition, SeekOrigin.Begin);
                                        fileStream.Write(buffer, 0, bytesRead);

                                        currentWritePosition += bytesRead;
                                        currentReadPosition += bytesRead;
                                    }

                                    fileStream.SetLength(currentWritePosition);

                                    foreach (var writer in lockPair.Writers)
                                    {
                                        if (writer._flushStart > _flushStart)
                                        {
                                            writer._flushStart -= totalCopiedBytes;
                                            writer._flushEnd -= totalCopiedBytes;
                                        }
                                    }
                                }
                            }
                            
                            fileStream.Seek(0, SeekOrigin.End);

                            _flushStart = totalCopiedBytes == -1 ? _flushStart : fileStream.Position - totalCopiedBytes;

                            try
                            {
                                if (writeHeader)
                                {
                                    var headerBytes = Encoding.UTF8.GetBytes($"---" + Environment.NewLine);
                                    fileStream.Write(headerBytes, 0, headerBytes.Length);
                                }
                                
                                if (File.Exists(_bufferFile))
                                {
                                    bool preserveLines = lockPair.Writers.Count > 1;
                                    lock (lockPair.BufferLock)
                                    {
                                        List<LineStream> streamsToUpdate = null;
                                        foreach (var lineStream in lockPair.LineStreams.Keys)
                                        {
                                            if (lineStream.Writer == this && lineStream.endPos != -1 && lineStream.startPos != -1)
                                            {
                                                lineStream.startPos = -1;
                                                lineStream.endPos = -1;
                                                lineStream.Flushed = true;
                                            }
                                            else
                                            {
                                                if (streamsToUpdate == null)
                                                    streamsToUpdate = new List<LineStream>();

                                                streamsToUpdate.Add(lineStream);
                                            }
                                        }
                                        
                                        using FileStream fs = new FileStream(_bufferFile, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
                                        using StreamReaderWithPosition reader = new StreamReaderWithPosition(fs, Encoding.UTF8);
                                        using StreamWriter writer = new StreamWriter(fs);
                                        long writePosition = 0;
                                        bool foundMatch = false;
                                        
                                        string line;
                                        while ((line = reader.ReadLine()) != null)
                                        {
                                            if (GetID(line) == ID)
                                            {
                                                foundMatch = true;
                                                
                                                string bufferText = line.Substring($"[{ID.ToString()}]-".Length) + Environment.NewLine;
                                                byte[] writeText = Encoding.UTF8.GetBytes(bufferText);
                                                fileStream.Write(writeText, 0, writeText.Length);
                                            }
                                            else if (preserveLines)
                                            {
                                                if (!foundMatch)
                                                {
                                                    writePosition = reader.Position;
                                                    continue;
                                                }
                                                
                                                long readPosition = fs.Position;
                                                
                                                fs.Position = writePosition;
                                                writer.WriteLine(line);
                                                writer.Flush();          
                                                writePosition = fs.Position;
                                                
                                                fs.Position = readPosition;
                                                
                                                if (streamsToUpdate != null)
                                                {
                                                    foreach (var lineStream in streamsToUpdate)
                                                    {
                                                        if (reader.Position == lineStream.startPos)
                                                        {
                                                            var size = lineStream.endPos - lineStream.startPos;
                                                            lineStream.startPos = writePosition;
                                                            lineStream.endPos = writePosition + size;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        fs.SetLength(writePosition);


                                    }
                                    if (!preserveLines)
                                        Wrap.ExecuteSafe(() => File.Delete(_bufferFile));
                                }
                            }
                            finally
                            {
                                fileStream.Flush();
                                _flushEnd = fileStream.Length;
                            }
                        }
                    }
                });

                if (exception != null)
                    Log.EnqueueExceptionSafe(exception, source: "Output Writer");
            }

            #region Private methods

            private void WriteBufferSafe(string type, [CanBeNull] string text, bool raw = false)
            {
                var exception = Wrap.ExecuteSafe(() =>
                {
                    if (!_locks.TryGetValue(OutputFile, out var lockPair) || !_writers.TryGetValue(this, out _))
                        return;
                    
                    var lines = text?.SplitByLine() ?? new[] { "" };

                    lock (lockPair.BufferLock)
                    {
                        if (!_writers.TryGetValue(this, out _))
                            return;
                        
                        using var fileStream = new FileStream(_bufferFile, FileMode.Append);

                        foreach (var line in lines)
                        {
                            string toWrite = $"[{ID}]-{(raw ? null : $"[{type} | {DateTime.UtcNow:HH:mm:ss}] ")}{line}" + Environment.NewLine;
                            var encodedText = Encoding.UTF8.GetBytes(toWrite);
                            fileStream.Write(encodedText, 0, encodedText.Length);
                        }

                        fileStream.Flush();
                    }
                });
                if (exception != null)
                    Log.EnqueueExceptionSafe(exception, source: "Output Writer");
            }
            
            private void InsertBufferSafe(string type, [CanBeNull] string text, LineStream lineStream)
            {
                var exception = Wrap.ExecuteSafe(() =>
                {
                    if (!_locks.TryGetValue(OutputFile, out var lockPair) || !_writers.TryGetValue(this, out _))
                        return;
                    
                    var lines = text?.SplitByLine();

                    lock (lockPair.BufferLock)
                    {
                        if (!_writers.TryGetValue(this, out _))
                            return;
                        
                        if (lineStream.startPos != -1 && lineStream.endPos != -1)
                        {
                            using var fileStream = new FileStream(_bufferFile, FileMode.OpenOrCreate, FileAccess.ReadWrite);

                            if (lines != null)
                            {
                                string formattedText = string.Empty;
                                foreach (var line in lines)
                                    formattedText += $"[{ID}]-[{type} | {DateTime.UtcNow:HH:mm:ss}] {line}" + Environment.NewLine;
                                var encoded = Encoding.UTF8.GetBytes(formattedText);

                                var shift =  encoded.Length - (lineStream.endPos - lineStream.startPos);
                                if (shift != 0)
                                {
                                    ShiftBytes(fileStream, lineStream.endPos, shift);
                                    foreach (var stream in lockPair.LineStreams.Keys)
                                    {
                                        if (stream != lineStream && stream.startPos != -1 && stream.endPos != -1 && stream.startPos > lineStream.startPos)
                                        {
                                            stream.startPos += shift;
                                            stream.endPos += shift;
                                        }
                                    }
                                }
                                fileStream.Seek(lineStream.startPos, SeekOrigin.Begin);
                                fileStream.Write(encoded, 0, encoded.Length);
                            }
                            else
                            {
                                var shift = -(lineStream.endPos - lineStream.startPos);
                                if (shift != 0)
                                {
                                    ShiftBytes(fileStream, lineStream.endPos, shift);
                                    foreach (var stream in lockPair.LineStreams.Keys)
                                    {
                                        if (stream != lineStream && stream.startPos != -1 && stream.endPos != -1 && stream.startPos > lineStream.startPos)
                                        {
                                            stream.startPos += shift;
                                            stream.endPos += shift;
                                        }
                                    }
                                }
                                fileStream.Seek(lineStream.startPos, SeekOrigin.Begin);
                            }
                            
                            fileStream.Flush();
                            lineStream.endPos = fileStream.Position;
                        }
                        else if (lines != null)
                        {
                            using var fileStream = new FileStream(_bufferFile, FileMode.Append);
                            lineStream.startPos = fileStream.Position;

                            foreach (var line in lines)
                            {
                                string toWrite = $"[{ID}]-[{type} | {DateTime.UtcNow:HH:mm:ss}] {line}" + Environment.NewLine;
                                var encodedText = Encoding.UTF8.GetBytes(toWrite);
                                fileStream.Write(encodedText, 0, encodedText.Length);
                            }

                            fileStream.Flush();
                            lineStream.endPos = fileStream.Position;
                        }
                    }
                });
                if (exception != null)
                    Log.EnqueueExceptionSafe(exception, source: "Output Writer");
            }
            
            private static void ShiftBytes(FileStream fs, long endPos, long shift)
            {
                const int bufferSize = 4096;
                byte[] buffer = new byte[bufferSize];
                long pos = endPos;

                if (shift < 0)
                {
                    while (pos < fs.Length)
                    {
                        int toRead = pos + bufferSize > fs.Length ? (int)(fs.Length - pos) : bufferSize;
                        fs.Position = pos;
                        fs.Read(buffer, 0, toRead);
                        fs.Position = pos + shift;
                        fs.Write(buffer, 0, toRead);
                        pos += toRead;
                    }
                    fs.SetLength(fs.Length + shift);
                }
                else if (shift > 0)
                {
                    pos = fs.Length;
                    fs.SetLength(pos + shift);

                    while (pos > endPos)
                    {
                        int toRead = (pos - endPos) < bufferSize ? (int)(pos - endPos) : bufferSize;
                        fs.Position = pos - toRead;
                        fs.Read(buffer, 0, toRead);
                        fs.Position = pos - toRead + shift;
                        fs.Write(buffer, 0, toRead);
                        pos -= toRead;
                    }
                }
            }

            [CanBeNull]
            private static int? GetID(string line)
            {
                try
                {
                    int startIdx = line.IndexOf('[') + 1;
                    int endIdx = line.IndexOf(']');

                    if (startIdx > 0 && endIdx > startIdx)
                    {
                        string idStr = line.Substring(startIdx, endIdx - startIdx);
                        if (int.TryParse(idStr, out int result))
                        {
                            return result;
                        }
                    }

                    return null;
                }
                catch
                {
                    return null;
                }
            }

            #endregion

            public void Dispose()
            {
                if (OutputFile == null)
                    return;
                
                _writers.TryRemove(this, out _);

                FlushSafe();

                if (_locks.TryGetValue(OutputFile, out var lockPair))
                {
                    lock (lockPair.BufferLock)
                    {
                        lockPair.Writers.Remove(this);

                        if (lockPair.Writers.Count == 0)
                            Wrap.ExecuteSafe(() => File.Delete(_bufferFile));
                    }
                    foreach (var lineStream in lockPair.LineStreams.Keys.Where(x => x.Writer == this))
                        lockPair.LineStreams.TryRemove(lineStream, out _);
                }
                else
                    Log.EnqueueSafe(LogType.Error, "Lock not found.", new SerializableTrace("Output Writer"));

                _outputIdManager.ReleaseId(ID);
            }

            public class LineStream : IDisposable
            {
                public readonly OutputWriter Writer;
                private readonly string _type;
                internal long startPos = -1;
                internal long endPos = -1;
                public LineStream([NotNull] OutputWriter writer, string type)
                {
                    (Writer, _type) = (writer, type);
                    if (Writer.OutputFile == null)
                        return;
                    if (!_locks.TryGetValue(Writer.OutputFile, out var lockPair))
                        throw new UnexpectedException("Lock not found.");
                    
                    lockPair.LineStreams.TryAdd(this, new byte());
                }

                public bool Flushed { get; set; } = false;
                public void WriteSafe([CanBeNull] string text)
                {
                    if (Writer.OutputFile == null)
                        return;
                    if (isDisposed)
                        throw new ObjectDisposedException(nameof(LineStream));
                    if (!_writers.TryGetValue(Writer, out _))
                        return;

                    Writer.InsertBufferSafe(_type, text ?? string.Empty, this);
                    Flushed = false;
                }
                public void Erase()
                {
                    if (Writer.OutputFile == null)
                        return;
                    if (isDisposed)
                        throw new ObjectDisposedException(nameof(LineStream));
                    if (!_writers.TryGetValue(Writer, out _))
                        return;

                    if (!Flushed)
                        Writer.InsertBufferSafe(_type, null, this);
                }
                
                private bool isDisposed = false;
                public void Dispose()
                {
                    if (isDisposed)
                        return;
                    isDisposed = true;
                    if (Writer.OutputFile == null)
                        return;
                    if (_locks.TryGetValue(Writer.OutputFile, out var lockPair))
                        lockPair.LineStreams.TryRemove(this, out _);
                }
            }
        }

        #endregion
    }
}