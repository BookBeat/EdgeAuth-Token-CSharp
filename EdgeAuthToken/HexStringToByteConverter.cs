using System;

namespace EdgeAuthToken
{
    internal static class HexStringToByteConverter
    {
        public static byte[] ToByteArray(string hex)
        {
            var len = hex.Length;
            var data = new byte[len / 2];
            for (var i = 0; i < len; i += 2)
            {
                int val1 = -1, val2 = -1;

                try
                {
                    val1 = Convert.ToInt32(hex[i].ToString(), 16) << 4;
                }
                catch (FormatException)
                {
                }
                catch (ArgumentException)
                {
                }

                try
                {
                    val2 = Convert.ToInt32(hex[i + 1].ToString(), 16);
                }
                catch (FormatException)
                {
                }
                catch (ArgumentException)
                {
                }

                val1 += val2;
                data[i / 2] = Convert.ToByte(val1);
            }
            return data;
        }
    }
}
