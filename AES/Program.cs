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
            byte[] eData = EncryptText(Klartext, keyBytes);

            string decData = DecryptText(eData, keyBytes);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Entschlüsselte Daten:\n");
            Console.ResetColor();
            Console.WriteLine(decData);
        }
        public static byte[] EncryptText(string inputText, byte[] aesKey)
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = aesKey;
                aesAlgorithm.Mode = CipherMode.CFB;
                aesAlgorithm.Padding = PaddingMode.PKCS7;

                // Initialisieren des IV (Initialisierungsvektor) - Wichtig für einige Modi
                aesAlgorithm.GenerateIV();
                byte[] iv = aesAlgorithm.IV;

                using (ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor())
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    // Zuerst den IV in die verschlüsselten Daten schreiben
                    memoryStream.Write(iv, 0, iv.Length);

                    byte[] textBytes = Encoding.UTF8.GetBytes(inputText);
                    cryptoStream.Write(textBytes, 0, textBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    
                    // Verschlüsselte Daten als Byte-Array
                    byte[] encryptedData = memoryStream.ToArray();
                    string b64Data = Convert.ToBase64String(encryptedData);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Verschlüsselte Daten: \n");
                    Console.ResetColor();   
                    Console.WriteLine("Base64 String: ");
                    Console.WriteLine(b64Data+"\n");
                    Console.WriteLine("Byte Array: ");
                    foreach (byte b in encryptedData)
                    {
                        Console.Write(b + " ");
                    }
                    Console.WriteLine("\n");
                    return encryptedData;
                }
            }
        }
        public static string DecryptText(byte[] encryptedData, byte[] aesKey)
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = aesKey;
                aesAlgorithm.Mode = CipherMode.CFB;
                aesAlgorithm.Padding = PaddingMode.PKCS7;

                // Der IV (Initialisierungsvektor) muss identisch mit dem beim Verschlüsseln verwendeten IV sein
                byte[] iv = new byte[aesAlgorithm.BlockSize / 8];
                Array.Copy(encryptedData, 0, iv, 0, iv.Length);
                aesAlgorithm.IV = iv;

                using (ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor())
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(encryptedData, iv.Length, encryptedData.Length - iv.Length);
                    cryptoStream.FlushFinalBlock();

                    byte[] decryptedBytes = memoryStream.ToArray();
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedText;
                }
            }
        }
    }
}

