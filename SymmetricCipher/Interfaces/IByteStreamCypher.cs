using System;
using System.Collections.Generic;
using System.Text;

namespace SymmetricCipher.Interfaces
{
	public interface IByteStreamCypher
	{
		void SetPassword(byte password);
		byte Encrypt(byte value);
		byte Decrypt(byte value);
	}
}
