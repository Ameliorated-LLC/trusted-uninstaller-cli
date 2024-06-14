using System;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Core
{
    public static class Helper
    {
        [DllImport("client-helper.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.BStr)]
        public static extern string FormatVolume(string letter, string formatType, uint allocationSize, string volumeLabel);

        [DllImport("client-helper.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.BStr)]
        public static extern string DeletePartitions(uint driveIndex);

        /// <summary>
        /// Only supports REG_SZ, REG_MULTI_SZ (I think), DWORD, and QWORD value types.
        /// </summary>
        [DllImport("client-helper.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.BStr)]
        public static extern string GetValue(IntPtr data, string key, string valueName);

        /// <summary>
        /// Gets all REG_SZ, REG_MULTI_SZ (I think), DWORD, and QWORD value types.
        /// The values are delimited by '\n', and the value name is separated from
        /// the value with the following 3 wide string: ":|:"
        /// </summary>
        [DllImport("client-helper.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.BStr)]
        public static extern string GetValues(IntPtr data, string key);

        public static ulong GetDWordValue(IntPtr data, string key, string valueName) =>
            uint.Parse(GetValue(data, key, valueName), NumberStyles.HexNumber);

        public static ulong GetQWordValue(IntPtr data, string key, string valueName) =>
            ulong.Parse(GetValue(data, key, valueName), NumberStyles.HexNumber);
    }
}