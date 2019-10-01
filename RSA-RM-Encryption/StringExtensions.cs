using System;

namespace Encryption
{
    public static class StringExtensions
    {
        /// <summary>
        /// Converts the passed hexadecimal encoded string to its byte[] equivalent.
        /// </summary>
        /// <param name="hexString">The hexadecimal encoded string to convert into a byte array.</param>
        public static byte[] ToByteArray(this string hexString)
        {
            if (!IsHex(hexString))
            {
                throw new ArgumentException($"StringExtensions.cs: ToByteArray() '{nameof(hexString)}' format error -> string must be hexadecimally encoded in order to convert to byte array.");
            }

            int hexLength = hexString.Length;
            byte[] hexBytes = new byte[hexLength / 2];
            for (int i = 0; i < hexLength; i += 2)
            {
                hexBytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            return hexBytes;
        }
        
        /// <summary>
        /// Converts a byte array to its hexadecimal encoded string equivalent.
        /// </summary>
        /// <param name="bytes">The bytes to convert to the hexadecimal encoded string.</param>
        public static string ToHexString(this byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }
        
        /// <summary>
        /// Determines if the passed string is hexadecimally formatted.
        /// </summary>
        /// <param name="str">The string of characters to verify.</param>
        private static bool IsHex(this string str)
        {
            for (int i = 0; i < str.Length; i++)
            {
                if (str[i] >= '0' && str[i] <= '9' || str[i] >= 'a' && str[i] <= 'f' || str[i] >= 'A' && str[i] <= 'F')
                    continue;

                return false;
            }

            return true;
        }
    }
}