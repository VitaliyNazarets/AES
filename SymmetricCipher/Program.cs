using SymmetricCipher.AESStreamModes;
using SymmetricCipher.Algorithms;
using SymmetricCipher.DataTest;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace SymmetricCipher
{
	class Program
	{
		static void Main(string[] args)
		{
			Stopwatch stopwatch = new Stopwatch();
			Salsa20Test salsa20Test = new Salsa20Test();
			Console.WriteLine("Salsa 20");
			var file = File.ReadAllBytes(@"E:\Projects\SymmetricCipher\SymmetricCipher\SymmetricCipher\DataTest\test.txt");
			salsa20Test.Run(stopwatch,file);
			Console.WriteLine("RC4");
			RC4DataTest test = new RC4DataTest();
			test.Run(stopwatch, file);
			Console.WriteLine("ECB");
			ECBTest ecb = new ECBTest();
			ecb.Run(stopwatch, file);
			Console.ReadKey();
		}
	}
}
