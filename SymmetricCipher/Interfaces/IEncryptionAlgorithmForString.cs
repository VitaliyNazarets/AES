using System;
using System.Collections.Generic;
using System.Text;

namespace SymmetricCipher.Algorithms
{
	public interface IEncryptionAlgorithmForString
	{
		string Encrypt(string value, string password);
		string Decrypt(string value, string password);
	}
}
