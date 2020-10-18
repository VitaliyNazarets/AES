using SymmetricCipher.Algorithms;
using System;
using System.Collections.Generic;
using System.Text;
using SymmetricCipher;
using System.Linq;

namespace SymmetricCipher.DataTest
{
	class RC4DataTest
	{
		public void Run()
		{
			RC4 rc4 = new RC4();
			byte[] password = new byte[16] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
			rc4.SetPassword(password);
			byte[] data = new byte[16];
			for (int i = 0; i < data.Length; i++)
				data[i] = (byte)(i % (byte.MaxValue + 1));
			byte[] encryptedData = new byte[16];
			int bSize = 1;
			for (int i = 0; i < data.Length / bSize; i++)
			{
				encryptedData.InsertInto(i, rc4.Encrypt(data.Skip(i * bSize).Take(bSize).ToArray()));
			}
			byte[] decryptedData = new byte[16];
			for (int i = 0; i < data.Length; i++)
			{
				decryptedData.InsertInto(i, rc4.Decrypt(encryptedData.Skip(i * bSize).Take(bSize).ToArray()));
			}
			Console.WriteLine(string.Join(" ", decryptedData));
			Console.ReadKey();
		}
	}
}
