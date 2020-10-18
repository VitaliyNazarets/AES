namespace SymmetricCipher.Algorithms
{
	public interface IEncryptionAlgorithm<T>
	{
		T Encrypt(T value, T password);

		T Decrypt(T value, T password);
	}
}
