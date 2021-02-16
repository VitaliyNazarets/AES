using System;
using Xunit;
using SymmetricCipher.Algorithms;

namespace SymmetricCipherUnitTests
{
	public class UnitTestsAES
	{
		[Theory]
		[InlineData(KeyType.Small_128, "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a")]
		[InlineData(KeyType.Medium_192, "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191")]
		[InlineData(KeyType.Big_256, "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"8ea2b7ca516745bfeafc49904b496089")]
		public void AES_Encrypt(KeyType keyType, string data, string key, string encryptedData)
		{
			var aes =  new AES(keyType);
			var result = aes.Encrypt(data, key);
			Assert.True(result == encryptedData, "AES Encrypt failed");
		}

		[Theory]
		[InlineData("")]
		[InlineData("123")]
		public void AES128_EncryptInvalidKeyLengthThrowsException(string key)
		{
			var aes = new AES(KeyType.Small_128);
			Assert.Throws<Exception>(() => aes.Encrypt("data", key));
		}

		[Theory]
		[InlineData(KeyType.Small_128, "69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff")]
		[InlineData(KeyType.Medium_192, "dda97ca4864cdfe06eaf70a0ec0d7191", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff")]
		[InlineData(KeyType.Big_256, "8ea2b7ca516745bfeafc49904b496089", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"00112233445566778899aabbccddeeff")]
		public void AES_Decrypt(KeyType keyType, string encryptedData, string key, string data)
		{
			var aes = new AES(keyType);
			var result = aes.Decrypt(encryptedData, key);
			Assert.True(result == data, "AES Encrypt failed");
		}

		[Theory]
		[InlineData("")]
		[InlineData("1")]
		[InlineData("1234567890")]
		public void AES_smallerThanExpectedBlockNotCrypted(string text)
		{
			var aes = new AES();
			var encrypted = aes.Encrypt(text, "000102030405060708090a0b0c0d0e0f");
			Assert.True(encrypted == text);
		}
	}
}
