using System;
using System.Collections.Generic;
using System.Text;

namespace SymmetricCipher.Algorithms
{
	public static class MixColumnsMulti
	{
		public static byte Gmul(byte a, byte b)
        { 
            byte p = 0;

            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool hi_bit_set = (a & 0x80) != 0;
                a <<= 1;
                if (hi_bit_set)
                {
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
                }
                b >>= 1;
            }
            return p;
        }
	}
}
