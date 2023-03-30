using System;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;

namespace TrustedUninstaller.Shared
{
    public static class DualOut
    {
        private static TextWriter _current;
        static MemoryMappedFile mmf = null;
        static MemoryMappedViewAccessor accessor = null;
        static int absolutePosition = 0;
        static int relativePosition = 0;
        private static string logDir = Directory.GetCurrentDirectory() + "\\Logs";

        private class OutputWriter : TextWriter
        {

            public override Encoding Encoding
            {
                get
                {
                    return _current.Encoding;
                }
            }

            public override void WriteLine(string value)
            {
                value = Regex.Replace(value, "(?<!\\r)\\n", "\r\n");
                
                _current.WriteLine(value);
                if (!WinUtil.IsTrustedInstaller())
                {
                    File.AppendAllText($"{logDir}\\AdminOutput.txt", value + Environment.NewLine);
                }
                else
                {
                    // Small window size to enforce roll-over for testing.
                    var windowSize = 2000000;

                    value += Environment.NewLine;

                    var bytes = Encoding.UTF8.GetBytes(value);

                    try
                    {
                        accessor = mmf.CreateViewAccessor(absolutePosition, windowSize, MemoryMappedFileAccess.ReadWrite);

                        if (bytes.Length + relativePosition > windowSize)
                        {
                            absolutePosition += relativePosition;
                            relativePosition = 0;
                            accessor.Dispose();
                            accessor = mmf.CreateViewAccessor(absolutePosition, windowSize, MemoryMappedFileAccess.ReadWrite);
                        }

                        accessor.WriteArray(relativePosition, bytes, 0, bytes.Length);
                        relativePosition += bytes.Length;
                    }
                    finally
                    {
                        if (accessor != null)
                            accessor.Dispose();
                    }

                    File.AppendAllText($"{logDir}\\TIOutput.txt", value + Environment.NewLine);
                    
                    // Small delay, less far less than a millisecond on most processors
                    Thread.SpinWait(40000);
                }
            }
            public override void WriteLine()
            {
                WriteLine("");
            }
        }

        public static void Init()
        {
            if (!Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }

            if (WinUtil.IsTrustedInstaller())
            {
                var i = 0;
                while (true)
                {
                    try
                    {
                        mmf = MemoryMappedFile.OpenExisting("ImgA");
                        break;
                    }
                    catch (FileNotFoundException)
                    {
                        if (i > 300) throw new Exception("Memory file not found.");
                        Task.Delay(200).Wait();
                        i++;
                    }
                }
            }

            _current = Console.Out;
            Console.SetOut(new OutputWriter());
        }
    }

}
