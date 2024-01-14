using AES;
using System;
using System.Security.Cryptography;
using System.Text;

namespace AesEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            // Generieren des 256-Bit AES Schlüssels
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("Aes 256-bit Verschlüsselung \n");
            Console.ResetColor();

            Console.WriteLine("Geben Sie den zu verschlüsselnden Klartext ein: \n");
            string Klartext = Console.ReadLine();
            Console.WriteLine("\n");
            AesKey key = new AesKey();
            string keyBase64 = key.GenerateAesKey();
            byte[] keyBytes = Convert.FromBase64String(keyBase64);
            Console.WriteLine("Byte Werte des Schlüssels:");

            foreach (byte b in keyBytes)
            {
                Console.Write(b + " ");
            }

            Console.WriteLine("\n");
            Console.WriteLine($"Schlüsselgröße:\n256-Bit\n");           

            AesEncrypt encrypt = new AesEncrypt();
            byte[] eData = encrypt.EncryptText(Klartext, keyBytes);

            AesDecrypt decrypt = new AesDecrypt();
            string decData = decrypt.DecryptText(eData, keyBytes);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Entschlüsselte Daten:\n");
            Console.ResetColor();
            Console.WriteLine(decData);
        }
        
    }
}

