using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Xml;

namespace SymmetricCipher.Algorithms
{
	public class AES : IEncryptionAlgorithm
	{
		private const int blockSize = 4;
		private int _rounds;
		private KeyType _keyType;
		private int _keyLength;
		private string _password;
		private byte[,] KeySchedule;
		private delegate bool Delegate(byte[,] input, out byte[,] byteResult);

		public AES(KeyType keyType = KeyType.Small_128)
		{
			UpdateKeyType(keyType);
		}

		public void UpdateKeyType(KeyType keyType)
		{
			_keyType = keyType;
			switch (keyType)
			{
				case KeyType.Small_128:
					_rounds = 10;
					break;
				case KeyType.Medium_192:
					_rounds = 12;
					break;
				case KeyType.Big_256:
					_rounds = 14;
					break;
			}
			_keyLength = (int)keyType / blockSize;
			KeySchedule = new byte[blockSize, (_rounds + 1) * blockSize];
		}

		#region PrivateSharedResources
		private void DataRound(int currentCharacter, string data, StringBuilder sb, Delegate func)
		{
			byte[,] dataBytes = new byte[blockSize, blockSize];
			byte[] dataArray = new byte[blockSize * blockSize];
			for (int i = currentCharacter * blockSize * blockSize; i < (currentCharacter + 1) * blockSize * blockSize; i++)
			{
				dataArray[i % (blockSize * blockSize)] = Convert.ToByte(data.Substring(i * 2, 2), 16);
			}
			for (int i = 0; i < dataArray.Length; i++)
			{
				dataBytes[i % blockSize, i / blockSize] = dataArray[i];
			}
			if (!func(dataBytes, out byte[,] byteResult))
				throw new Exception("Can't encrypt data");
			for (int j = 0; j < blockSize; j++)
			{
				for (int k = 0; k < blockSize; k++)
				{
					sb.Append($"{byteResult[k, j]:x2}");
				}
			}
		}
		private void SetPassword(string key)
		{
			if (string.IsNullOrEmpty(_password) || _password != key)
			{
				if (key.Length / 2 != (int)_keyType)
					throw new Exception(string.Format("Key requires {0}", (int)_keyType));
				_password = key;
				byte[] keyArray = new byte[_password.Length / 2];
				for (int i = 0; i < _password.Length / 2; i++)
				{
					keyArray[i] = Convert.ToByte(_password.Substring(i * 2, 2), 16);
				}
				byte[,] keyTable = new byte[blockSize, _keyLength];
				for (int i = 0; i < keyArray.Length; i++)
				{
					keyTable[i % blockSize, i / blockSize] = keyArray[i];
				}
				KeyExpansion(keyTable);
			}
		}
		private void AddRoundKey(ref byte[,] state, int round)
		{
			for (int i = 0; i < blockSize; i++)
			{
				for (int j = 0; j < blockSize; j++) 
					state[i, j] ^= KeySchedule[i, j + round * blockSize];
			}
		}
		private void KeyExpansion(byte[,] key)
		{
			//First 
			for (int i = 0; i < blockSize; i++)
			{
				for (int j = 0; j < _keyLength; j++)
					KeySchedule[i, j] = key[i, j];
			}
			byte[] tmp = new byte[blockSize];
			for (int col = _keyLength; col < (_rounds + 1) * blockSize; col++)
			{
				for (int i = 0; i < blockSize; i++)
				{
					tmp[i] = KeySchedule[i, col - 1];
				}
				if (col % (_keyLength) == 0)
				{
					//RotWord
					byte temp = tmp[0];
					for (int i = 0; i < blockSize - 1; i++)
					{
						tmp[i] = tmp[i + 1];
					}
					tmp[blockSize - 1] = temp;

					//change elements using Sbox
					for (int j = 0; j < blockSize; j++)
					{
						tmp[j] = SBox.Data[tmp[j] / 0x10, tmp[j] % 0x10];
					}
					//xor Rcon
					tmp[0] ^= Rcon.Data[col / _keyLength];
				}
				else if (_keyLength > 6 && col % _keyLength == 4)
				{
					for (int j = 0; j < blockSize; j++)
					{
						tmp[j] = SBox.Data[tmp[j] / 0x10, tmp[j] % 0x10];
					}
				}
				for (int i = 0; i < blockSize; i++)
					KeySchedule[i, col] = (byte)(KeySchedule[i, col - _keyLength] ^ tmp[i]);
			}
		}
		#endregion

		#region Encrypt
		public string Encrypt(string data, string key)
		{
			SetPassword(key);
			int i = 0;
			StringBuilder sb = new StringBuilder();
			Delegate deleg = new Delegate(Encrypt);
			while (i < data.Length / 32)
			{
				DataRound(i, data, sb, deleg);
				i++;
			}
			if (i * 32 != data.Length)
			{
				sb.Append(data.Substring(i * 32));
			}
			return sb.ToString();
		}
		private bool Encrypt(byte[,] input, out byte[,] output)
		{
			var state = (byte[,]) input.Clone();
			AddRoundKey(ref state, 0);
			for (int round = 1; round < _rounds; round++)
			{
				SubBytes(ref state);
				ShiftRows(ref state);
				MixColumns(ref state);
				AddRoundKey(ref state, round);
			}
			SubBytes(ref state);
			ShiftRows(ref state);
			AddRoundKey(ref state, _rounds);
			output = state;
			return true;
		}
		private void MixColumns(ref byte[,] state)
		{
			for (int j = 0; j < blockSize; j++)
			{
				byte[] newColumn = new byte[blockSize];
				newColumn[0] = (byte)(MixColumnsMulti.Gmul(0x02, state[0, j]) ^ MixColumnsMulti.Gmul(0x03, state[1, j]) ^ state[2, j] ^ state[3, j]);
				newColumn[1] = (byte)(state[0, j] ^ MixColumnsMulti.Gmul(0x02, state[1, j]) ^ MixColumnsMulti.Gmul(0x03, state[2, j]) ^ state[3, j]);
				newColumn[2] = (byte)(state[0, j] ^ state[1, j] ^ MixColumnsMulti.Gmul(0x02, state[2, j]) ^ MixColumnsMulti.Gmul(0x03, state[3, j]));
				newColumn[3] = (byte)(MixColumnsMulti.Gmul(0x03, state[0, j]) ^ state[1, j] ^ state[2, j] ^ MixColumnsMulti.Gmul(0x02, state[3, j]));
				for (int i = 0; i < blockSize; i++)
				{
					state[i, j] = newColumn[i];
				}
			}
		}
		private void ShiftRows(ref byte[,] state)
		{
			byte t = state[1, 0];
			//second row
			for (int j = 0; j < blockSize; j++)
			{
				state[1, j] = state[1, (j + 1) % blockSize];
			}
			state[1, blockSize - 1] = t;
			//third row
			t = state[2, 0];
			state[2, 0] = state[2, 2];
			state[2, 2] = t;
			t = state[2, 1];
			state[2, 1] = state[2, 3];
			state[2, 3] = t;
			//fourth row
			t = state[3, 0];
			state[3, 0] = state[3, 3];
			state[3, 3] = state[3, 2];
			state[3, 2] = state[3, 1];
			state[3, 1] = t;
		}
		private void SubBytes(ref byte[,] state)
		{
			for (int i = 0; i < blockSize; i++)
				for (int j = 0; j < blockSize; j++)
					state[i, j] = SBox.Data[state[i, j] / 16, state[i, j] % 16];
		}
		#endregion
	
		#region Decrypt
		public string Decrypt(string data, string key)
		{
			SetPassword(key);
			int i = 0;
			StringBuilder sb = new StringBuilder();
			Delegate deleg = new Delegate(Decrypt);
			while (i < data.Length / 32)
			{
				DataRound(i, data, sb, deleg);
				i++;
			}
			if (i * 32 != data.Length)
			{
				sb.Append(data.Substring(i * 32));
			}
			return sb.ToString();
		}
		private bool Decrypt(byte[,] input, out byte[,] output)
		{
			var state = (byte[,])input.Clone();
			int currentRound = _rounds;
			AddRoundKey(ref state, currentRound);
			currentRound--;
			while (currentRound > 0)
			{
				InvShiftRows(ref state);
				InvSubBytes(ref state);
				AddRoundKey(ref state, currentRound);
				InvMixColumns(ref state);
				currentRound--;
			}
			InvShiftRows(ref state);
			InvSubBytes(ref state);
			AddRoundKey(ref state, currentRound);
			output = state;
			return true;
		}
		private void InvSubBytes(ref byte[,] state)
		{
			for (int i = 0; i < blockSize; i++)
				for (int j = 0; j < blockSize; j++)
					state[i, j] = InvSbox.Data[state[i, j] / 16, state[i, j] % 16];
		}
		private void InvShiftRows(ref byte[,] state)
		{
			byte t;
			//second row
			t = state[1, 0];
			state[1, 0] = state[1, 3];
			state[1, 3] = state[1, 2];
			state[1, 2] = state[1, 1];
			state[1, 1] = t;

			//third row
			t = state[2, 0];
			state[2, 0] = state[2, 2];
			state[2, 2] = t;
			t = state[2, 1];
			state[2, 1] = state[2, 3];
			state[2, 3] = t;

			//fourth row
			t = state[3, 0];
			for (int j = 0; j < blockSize; j++)
			{
				state[3, j] = state[3, (j + 1) % blockSize];
			}
			state[3, blockSize - 1] = t;
		}
		private void InvMixColumns(ref byte[,] state)
		{
			for (int j = 0; j < blockSize; j++)
			{
				byte[] newColumn = new byte[blockSize];
				newColumn[0] = (byte)(MixColumnsMulti.Gmul(0x0e, state[0, j]) ^ MixColumnsMulti.Gmul(0x0b, state[1, j]) ^ MixColumnsMulti.Gmul(0x0d, state[2, j]) ^ MixColumnsMulti.Gmul(0x09, state[3, j]));
				newColumn[1] = (byte)(MixColumnsMulti.Gmul(0x09, state[0, j]) ^ MixColumnsMulti.Gmul(0x0e, state[1, j]) ^ MixColumnsMulti.Gmul(0x0b, state[2, j]) ^ MixColumnsMulti.Gmul(0x0d, state[3, j]));
				newColumn[2] = (byte)(MixColumnsMulti.Gmul(0x0d, state[0, j]) ^ MixColumnsMulti.Gmul(0x09, state[1, j]) ^ MixColumnsMulti.Gmul(0x0e, state[2, j]) ^ MixColumnsMulti.Gmul(0x0b, state[3, j]));
				newColumn[3] = (byte)(MixColumnsMulti.Gmul(0x0b, state[0, j]) ^ MixColumnsMulti.Gmul(0x0d, state[1, j]) ^ MixColumnsMulti.Gmul(0x09, state[2, j]) ^ MixColumnsMulti.Gmul(0x0e, state[3, j]));
				for (int i = 0; i < blockSize; i++)
				{
					state[i, j] = newColumn[i];
				}
			}
		}
		#endregion
	}
}
