using SymmetricCipher.Algorithms;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SymmetricCipher.AESStreamModes
{
	class CipherBlockChaining
	{
		private readonly byte[] vectorIV = new byte[16];
		private readonly AES _aes = new AES(KeyType.Small_128);
		private const int blockSize = 16;
		private byte[] _password = null;

		public CipherBlockChaining()
		{
			for (byte i = 0; i < vectorIV.Length; i++)
				vectorIV[i] = (byte)i;
		}

		public byte[] Encrypt(byte[] data)
		{
			if (_password is null)
				throw new Exception("Password not set");
			int length = (data.Length / blockSize) * blockSize < data.Length ? (data.Length / blockSize) * blockSize + blockSize : data.Length;
			byte[] encryptedData = new byte[length];
			for (int i = 0; i < length; i++)
			{
				encryptedData.InsertInto(i * blockSize, _aes.Encrypt(data.Skip(i * blockSize).Take(blockSize).ToArray(), _password));
			}
			return encryptedData;
		}

		public byte[] Decrypt(byte[] data)
		{
			if (_password is null)
				throw new Exception("Password not set");
			int length = (data.Length / blockSize) * blockSize < data.Length ? (data.Length / blockSize) * blockSize + blockSize : data.Length;
			byte[] encryptedData = new byte[length];
			for (int i = 0; i < length; i++)
			{
				encryptedData.InsertInto(i * blockSize, _aes.Encrypt(data.Skip(i * blockSize).Take(blockSize).ToArray(), _password));
			}
			return encryptedData;
		}

		public void SetPassword(byte[] password)
		{
			if (password.Length != 16)
				throw new Exception("Password length != 16");
			_password = password;
		}

	}
}
