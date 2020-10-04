using System;
using Xunit;
using SymmetricCipher.Algorithms;

namespace SymmetricCipherUnitTests
{
	public class UnitTestsAES
	{
		readonly AES aES128 = new AES(KeyType.Small_128);
		readonly AES aes192 = new AES(KeyType.Medium_192);
		readonly AES aes256 = new AES(KeyType.Big_256);
		[Fact]
		public void C1AES128_Encrypt()
		{
			var result = aES128.Encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f");
			Assert.True(result == "69c4e0d86a7b0430d8cdb78070b4c55a", "C.1 AES 128 Encrypt failed");
		}
		[Fact]
		public void C1EAS128_Decrypt()
		{
			var result = aES128.Decrypt("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f");
			Assert.True(result == "00112233445566778899aabbccddeeff", "C.1 AES 128 Decrypt failed");
		}
		[Fact]
		public void C2AES192_Encrypt()
		{
			var result = aes192.Encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617");
			Assert.True(result == "dda97ca4864cdfe06eaf70a0ec0d7191", "C.2 AES 192 Encrypt failed");
		}
		[Fact]
		public void C2AES192_Decrypt()
		{
				var result = aes192.Decrypt("dda97ca4864cdfe06eaf70a0ec0d7191", "000102030405060708090a0b0c0d0e0f1011121314151617");
				Assert.True(result == "00112233445566778899aabbccddeeff", "C.2 AES 192Decrypt failed");
		}

		[Fact]
		public void C2AES256_Encrypt()
		{
			var result = aes256.Encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
			Assert.True(result ==
			"8ea2b7ca516745bfeafc49904b496089", "C.3 AES 256 Encrypt failed");
		}
		[Fact]
		public void C2AES256_Decrypt()
		{
			var result = aes256.Decrypt("8ea2b7ca516745bfeafc49904b496089", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
			Assert.True(result =="00112233445566778899aabbccddeeff", "C.2 AES 256 Decrypt failed");
		}
	}
}
