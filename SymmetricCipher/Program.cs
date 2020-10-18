using SymmetricCipher.AESStreamModes;
using SymmetricCipher.Algorithms;
using SymmetricCipher.DataTest;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace SymmetricCipher
{
	class Program
	{
		static void Main(string[] args)
		{
			byte[] password = new byte[32];
			for (int i = 0; i < password.Length; i++)
				password[i] = (byte)i;

			Salsa20 salsa20 = new Salsa20();
			salsa20.SetPassword(password);
			int size = 64;
			byte[] data = new byte[size];
			for (int i = 0; i < size; i++)
				data[i] = (byte)(i % 256);
			var encryptedData = salsa20.Encrypt(data);
			var decryptedData = salsa20.Decrypt(encryptedData);
			Console.WriteLine(string.Join(" ", encryptedData));
			Console.WriteLine(string.Join(" ", decryptedData));
			Console.ReadKey();
		}
	}
}
