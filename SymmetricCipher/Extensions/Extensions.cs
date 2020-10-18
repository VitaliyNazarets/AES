namespace SymmetricCipher
{
	static class Extensions
	{
		public static void Swap<T>(this T[] array, int index1, int index2)
		{
			T temp = array[index1];
			array[index1] = array[index2];
			array[index2] = temp;
		}
		public static void InsertInto<T>(this T[] array, int index, T[] array2)
		{
			for (int i = 0; i < array2.Length && (i + index) < array.Length; i++)
			{
				array[i + index] = array2[i];
			}
		}
	}
}
