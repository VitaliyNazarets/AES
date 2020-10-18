using SymmetricCipher.Algorithms;
using SymmetricCipher.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymmetricCipher.Algorithms
{
	public class RC4 : IStreamCypher<byte[]>
	{
		readonly byte[] S = new byte[256];
		private bool _isEncrypt = true;
		private int countI = 0, countJ = 0;
		private byte[] _password = null;

		private void RC4KeyShedule(byte[] Password)
		{
			for (int i = 0; i < S.Length; i++) 
			{
				S[i] = (byte)i;
			}
			int j = 0;
			for (int i = 0; i < S.Length; i++)
			{
				j = (j + S[i] + Password[i % Password.Length]) % 256;
				S.Swap(i, j);
			}
		}

		private byte ByteEncription()
		{
			countI = (countI + 1) % 256;
			countJ = (countJ + S[countI]) % 256;
			S.Swap(countI, countJ);
			return S[(S[countI] + S[countJ]) % 256];
		}

		public void SetPassword(byte[] password)
		{
			RC4KeyShedule(password);
			_password = password;
		}

		public byte[] Encrypt(byte[] value)
		{
			if (!_isEncrypt)
			{
				countI = 0;
				countJ = 0;
				RC4KeyShedule(_password);
				_isEncrypt = true;
			}
			if (_password is null)
				throw new Exception("Password not set");
			return Encryption(value);
		}

		private byte[] Encryption(byte[] data)
		{
			byte[] cipher = new byte[data.Length];
			for (int m = 0; m < data.Length; m++)
			{
				cipher[m] = (byte)( ByteEncription() ^ data[m]);
			}
			return cipher;
		}

		public byte[] Decrypt(byte[] value)
		{
			if (_isEncrypt)
			{
				countI = 0;
				countJ = 0;
				RC4KeyShedule(_password);
				_isEncrypt = false;
			}
			if (_password is null)
				throw new Exception("Password not set");
			return Encryption(value);
		}
	}
}
