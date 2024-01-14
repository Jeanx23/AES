using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    public class AesDecrypt
    {
        public string DecryptText(byte[] encryptedData, byte[] aesKey)
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
