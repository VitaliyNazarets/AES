namespace SymmetricCipher.Algorithms
{
	public interface IStreamCypher<T>
	{
		void SetPassword(T password);
		T Encrypt(T value);
		T Decrypt(T value);
	}
}
