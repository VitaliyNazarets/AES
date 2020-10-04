using SymmetricCipher.Algorithms;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace SymmetricCipher.DataTest
{
	public class FileEncryptor
	{
		public void DecryptFile(IEncryptionAlgorithm encryptor, string password, Stopwatch stopwatch, string fileReadPath, string fileWritePath)
		{
			var text = File.ReadAllText(fileReadPath);
			stopwatch.Start();
			var result = encryptor.Decrypt(text, password);
			stopwatch.Stop();
			File.WriteAllText(fileWritePath, result);
		}

		public void EncryptFile(IEncryptionAlgorithm encryptor, string password, Stopwatch stopwatch, string fileReadPath, string fileWritePath )
		{
			var text = File.ReadAllText(fileReadPath);
			stopwatch.Start();
			var result = encryptor.Encrypt(text, password);
			stopwatch.Stop();
			File.WriteAllText(fileWritePath, result);
		}
	}
}
