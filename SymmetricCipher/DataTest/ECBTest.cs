using SymmetricCipher.AESStreamModes;
using System;
using System.Collections.Generic;
using System.Text;

namespace SymmetricCipher.DataTest
{
	public class ECBTest
	{
		public void Run()
		{
			byte[] password = new byte[16] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
			ElectronicCodeBook ecb = new ElectronicCodeBook();
			ecb.SetPassword(password);
			int size = 16;
			byte[] data = new byte[size];
			for (int i = 0; i < size; i++)
				data[i] = (byte)(i % 256);
			var encryptedData = ecb.Encrypt(data);
			var decryptedData = ecb.Decrypt(encryptedData);
		}
	}
}
