using System;

namespace Core
{
    public class StringUtils
    {
        public static string HumanReadableBytes(ulong input)
        {

            double size = input;
            string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB" };
            int order = 0;
            while (size >= 1024 && order < suffixes.Length - 1)
            {
                order++;
                size = size / 1024;
            }
            double roundedAndFormattedSize = Math.Round((double)size, 0);
            return $"{roundedAndFormattedSize} {suffixes[order]}";
        }
        public static string HumanReadableDiskSize(long input)
        {
            long dividedSize = input;
            string suffix = "";
            foreach (var sizeSuffix in new[] { "KB", "MB", "GB", "TB", "PB" })
            {
                dividedSize /= 1000;
                if (dividedSize < 1000)
                {
                    suffix = sizeSuffix;
                    break;
                }
            }

            if (dividedSize < 8)
            {
                var result = (Math.Abs((dividedSize * 10.0) - (Math.Floor(dividedSize + 0.5) * 10.0)) < 0.5)
                    ? Math.Truncate((double)dividedSize)
                    : Math.Truncate((double)(dividedSize * 10)) / 10;
                return result + " " + suffix;
            }
            else
            {
                int t = (int)dividedSize;

                t--;
                t |= t >> 1;
                t |= t >> 2;
                t |= t >> 4;
                t |= t >> 8;
                t++;

                var result = (Math.Abs(1.0f - (dividedSize / (double)t)) < 0.05f) ? (double)t : dividedSize;
                return result + " " + suffix;
            }
        }
    }
}