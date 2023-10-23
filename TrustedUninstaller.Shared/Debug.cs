using System;
using System.Diagnostics;

namespace TrustedUninstaller.Shared
{
    public static class Testing
    {
        [Conditional("DEBUG")]
        public static void WriteLine(object text)
        {
            Console.WriteLine(text.ToString());
        }
        public static void WriteLine(Exception exception, string shortTrace)
        {
            Console.WriteLine(exception.GetType() + " at " + shortTrace + ":" + exception.Message);
        }
        public static void WriteLine(Exception exception, string shortTrace, string item)
        {
            Console.WriteLine(exception.GetType() + " at " + shortTrace + $" ({item}):" + exception.Message);
        }
    }
}
