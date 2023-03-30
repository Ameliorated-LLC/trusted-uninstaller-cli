
using System;
using System.IO;
using System.Windows.Forms;

namespace TrustedUninstaller.Shared
{
    public class ErrorLogger
    {

        public static void WriteToErrorLog(string msg, string stkTrace, string title, string? item = null)
        {
            if (!(Directory.Exists(Directory.GetCurrentDirectory() + "\\Logs")))
            {

                Directory.CreateDirectory(Directory.GetCurrentDirectory() + "\\Logs");

            }

            try
            {
                FileStream fs = new FileStream(Directory.GetCurrentDirectory() + "\\Logs\\ErrorLog.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite);

                StreamWriter s = new StreamWriter(fs);

                s.Close();

                fs.Close();

                FileStream fs1 = new FileStream(Directory.GetCurrentDirectory() + "\\Logs\\ErrorLog.txt", FileMode.Append, FileAccess.Write);

                StreamWriter s1 = new StreamWriter(fs1);

                s1.WriteLine("Title: " + title);

                s1.WriteLine("Message: " + msg.TrimEnd('\n').TrimEnd('\r'));

                if (stkTrace != null) s1.WriteLine(Environment.NewLine + "StackTrace: " + stkTrace + Environment.NewLine);
                
                if (item != null) s1.WriteLine("Object: " + item);

                s1.WriteLine("Date/Time: " + DateTime.Now);

                s1.WriteLine

                    ("============================================");

                s1.Close();

                fs1.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR WRITING INTO THE ERROR LOG: " + e.Message);
            }
        }
    }
}