using System;
using System.Collections.Generic;
using static System.Console;


namespace InformappEncryptionTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var keyIV = EncryptionHelper.GenerateKeyAndIV();

            List<string> starts = new List<string>() {
                "Password12345!",
                "My name is Rafael",
                "How is life?"
            };

            WriteLine($"key:       {keyIV.Item1}");
            WriteLine($"IV:        {keyIV.Item2}");
            WriteLine();

            foreach (var start in starts)
            {
                var encrypted = start.Encrypt(keyIV);
                var decrypted = encrypted.Decrypt(keyIV);
                WriteLine($"start:     {start}");
                WriteLine($"encrypted: {encrypted}");
                WriteLine($"decrypted: {decrypted}");
                WriteLine();
            }           
        }
    }
}
