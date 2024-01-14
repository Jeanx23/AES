using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AesEncryption
{
    public class AesEncrypt
    {
        public byte[] EncryptText(string inputText, byte[] aesKey)
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
                    Console.WriteLine(b64Data + "\n");
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
    }
}
