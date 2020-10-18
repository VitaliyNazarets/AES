using SymmetricCipher.Algorithms;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SymmetricCipher
{
	class Salsa20 : IStreamCypher<byte[]>
	{
		private uint position = 0;
		private bool isEncrypt = true;
		private readonly uint[] key = new uint[8];

		private uint[] GetNonce()
		{
			return new uint[] { position + 123, position + 1 };
		}
		private uint[] GetInitialState()
		{
			uint[] State = new uint[16];
			//0 1 2 3
			//4 5 6 7
			//8 9 10 11
			//12 13 14 15
			//expand 32-byte k
			State[0] = 0x61707865;
			State[5] = 0x3320646e;
			State[10] = 0x79622d32;
			State[15] = 0x6d206574;
			//Key
			if (key.Length != 8)
				throw new Exception("Key size != 8");
			for (int i = 0; i < 3; i++)
				State[i + 1] = key[i];
			State[4] = key[3];
			State[11] = key[4];
			for (int i = 5; i < 8; i++)
				State[7 + i] = key[i];
			//Nonce
			var Nonce = GetNonce();
			State[6] = Nonce[0];
			State[7] = Nonce[1];
			//position now;
			State[8] = position;
			State[9] = position;
			return State;
		}

		private (uint, uint, uint, uint) QuarterRound(uint y0, uint y1, uint y2, uint y3)
		{
			uint z1, z2, z3, z4;
			z1 = y1 ^ ((y0 + y3)  << 7);
			z2 = y2 ^ ((y1 + y0) << 9);
			z3 = y3 ^ ((y2 + y1) << 13);
			z4 = y0 ^ ((y3 + y2)  << 18);
			return (z1, z2, z3, z4);
		}

		private uint[] RowRound(uint[] y)
		{
			uint[] z = new uint[y.Length];
			(z[0], z[1], z[2], z[3]) = QuarterRound(y[0], y[1], y[2], y[3]);
			(z[5], z[6], z[7], z[4]) = QuarterRound(y[5], y[6], y[7], y[4]);
			(z[10], z[11], z[8], z[9]) = QuarterRound(y[10], y[11], y[8], y[9]);
			(z[15], z[12], z[13], z[14]) = QuarterRound(y[15], y[12], y[13], y[14]);
			return z;
		}

		private uint[] ColumnRound(uint[] y)
		{
			uint[] z = new uint[y.Length];
			(z[0], z[4], z[8], z[12]) = QuarterRound(y[0], y[4], y[8], y[12]);
			(z[5], z[9], z[13], z[1]) = QuarterRound(y[5], y[9], y[13], y[1]);
			(z[10], z[14], z[2], z[6]) = QuarterRound(y[10], y[14], y[2], y[6]);
			(z[15], z[3], z[7], z[11]) = QuarterRound(y[15], y[3], y[7], y[11]);
			return z;
		}
		
		private uint[] DoubleRound(uint[] y)
		{
			return RowRound(ColumnRound(y));
		}

		public void SetPassword(byte[] password)
		{
			if (password.Length != 32)
				throw new Exception("Password byte range != 32");
			for (int i = 0; i < 8; i++)
			{
				key[i] = Littleendiand(password[i * 4], password[i * 4 + 1], password[i * 4 + 2], password[i * 4 + 3]);
			}
		}

		private uint Littleendiand(byte x0, byte x1, byte x2, byte x3)
		{
			return (uint)(x0 + x1 * Math.Pow(2, 8) + x2 * Math.Pow(2, 16) + x3 * Math.Pow(2, 24));
		}

		private byte[] GetBytesFromUint(uint value)
		{
			var v1 = (byte)(value / Math.Pow(2, 24));
			var v2 = (byte)((value - v1 * Math.Pow(2, 24)) / Math.Pow(2, 16));
			var v3 = (byte)((value - v1 * Math.Pow(2, 24) - v2 * Math.Pow(2, 16)) / Math.Pow(2, 8));
			var v4 = (byte)((value - v1 * Math.Pow(2, 24) - v2 * Math.Pow(2, 16) - v3 * Math.Pow(2, 8)));
			return new byte[] { v1, v2, v3, v4 };
		}

		private byte[] Salsa20Alg(byte[] data)
		{
			uint[] y = GetInitialState();
			if (data.Length != 64)
				throw new Exception("Only 64 byte length supported");
			uint[] dataResult = new uint[16];
			for (int i = 0; i < dataResult.Length; i++)
			{
				dataResult[i] = Littleendiand(data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3]);
			}
			for (int i = 0; i < 10; i++)
			{
				var t = DoubleRound(y);
				for (int j = 0; j < y.Length; j++)
					y[j] = y[j] ^ t[j];
			}

			for (int i = 0; i < dataResult.Length; i++)
			{
				dataResult[i] ^= y[i];
			}
			position++;
			byte[] returnData = new byte[64];
			for (int i = 0; i < dataResult.Length; i++)
			{
				returnData.InsertInto(i * 4, GetBytesFromUint(dataResult[i]));
			}
			return returnData;
		}

		public byte[] Encrypt(byte[] value)
		{
			if (!isEncrypt)
			{
				(position, isEncrypt) = (0, true);
			}
			return Salsa20Alg(value);
		}

		public byte[] Decrypt(byte[] value)
		{
			if (isEncrypt)
			{
				(position, isEncrypt) = (0, false);
			}
			return  Salsa20Alg(value);
		}
	}
}
