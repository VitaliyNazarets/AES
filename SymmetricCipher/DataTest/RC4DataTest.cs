using SymmetricCipher.Algorithms;
using System;
using System.Collections.Generic;
using System.Text;
using SymmetricCipher;
using System.Linq;
using System.Diagnostics;

namespace SymmetricCipher.DataTest
{
	class RC4DataTest
	{
		public void Run(Stopwatch stopwatch, byte[] data)
		{
			RC4 rc4 = new RC4();
			byte[] password = new byte[16] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
			rc4.SetPassword(password);
			byte[] encryptedData = new byte[data.Length];
			byte[] decryptedData = new byte[data.Length];

			int bSize = 1;
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < data.Length / bSize; i++)
			{
				encryptedData.InsertInto(i, rc4.Encrypt(data.Skip(i * bSize).Take(bSize).ToArray()));
			}
			stopwatch.Stop();
			Console.WriteLine(string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
			stopwatch.Elapsed.Hours, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds,
			stopwatch.Elapsed.Milliseconds / 10));
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < data.Length; i++)
			{
				decryptedData.InsertInto(i, rc4.Decrypt(encryptedData.Skip(i * bSize).Take(bSize).ToArray()));
			}

			stopwatch.Stop();
			Console.WriteLine(string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
			stopwatch.Elapsed.Hours, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds,
			stopwatch.Elapsed.Milliseconds / 10));
		}
	}
}
