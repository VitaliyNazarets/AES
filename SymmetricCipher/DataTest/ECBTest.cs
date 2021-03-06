﻿using SymmetricCipher.AESStreamModes;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace SymmetricCipher.DataTest
{
	public class ECBTest
	{
		public void Run(Stopwatch stopwatch, byte[] data)
		{
			byte[] password = new byte[16] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
			ElectronicCodeBook ecb = new ElectronicCodeBook();
			ecb.SetPassword(password);
			byte[] encryptedData = new byte[data.Length];
			byte[] decryptedData = new byte[data.Length];
			stopwatch.Reset();
			stopwatch.Start();
			for (int i = 0; i < data.Length / 64; i++)
			{
				var dataToEncrypt = data.Skip(i * 64).Take(64).ToArray();
				if (dataToEncrypt.Length != 64)
					Array.Resize(ref dataToEncrypt, 64);
				encryptedData.InsertInto(i, ecb.Encrypt(dataToEncrypt));
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
				decryptedData.InsertInto(i, ecb.Encrypt(dataToDecrypt));
			}
			stopwatch.Stop();
			Console.WriteLine(string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
			stopwatch.Elapsed.Hours, stopwatch.Elapsed.Minutes, stopwatch.Elapsed.Seconds,
			stopwatch.Elapsed.Milliseconds / 10));
		}
	}
}
