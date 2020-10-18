using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SymmetricCipher.DataTest
{
	public class Salsa20Test
	{
		public void Run(Stopwatch stopwatch, byte[] data)
		{
			byte[] password = new byte[32];
			for (int i = 0; i < password.Length; i++)
				password[i] = (byte)i;

			Salsa20 salsa20 = new Salsa20();
			salsa20.SetPassword(password);
			int size = 64;
			byte[] encryptedData = new byte[data.Length];
			byte[] decryptedData = new byte[data.Length];
			for (int i = 0; i < size; i++)
				data[i] = (byte)(i % 256);
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < data.Length / 64; i++)
			{
				var dataToEncrypt = data.Skip(i * 64).Take(64).ToArray();
				if (dataToEncrypt.Length != 64)
					Array.Resize(ref dataToEncrypt, 64);
				encryptedData.InsertInto(i, salsa20.Encrypt(dataToEncrypt));
			}
			stopwatch.Stop();
			Console.WriteLine(string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
			stopwatch.Elapsed.Hours, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds,
			stopwatch.Elapsed.Milliseconds / 10));
			stopwatch.Reset();

			stopwatch.Start();
			for (int i = 0; i < data.Length / 64; i++)
			{
				var dataToDecrypt = data.Skip(i * 64).Take(64).ToArray();
				if (dataToDecrypt.Length != 64)
					Array.Resize(ref dataToDecrypt, 64);
				decryptedData.InsertInto(i, salsa20.Decrypt(dataToDecrypt));
			}
			stopwatch.Stop();
			Console.WriteLine(string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
			stopwatch.Elapsed.Hours, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds,
			stopwatch.Elapsed.Milliseconds / 10));
		}
	}
}
