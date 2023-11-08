using System;
using System.Security.Cryptography;

namespace AesEncryption
{
    public class AesKey
    {
        public string GenerateAesKey()
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.KeySize = 256;
                aesAlgorithm.GenerateKey();
                string keyBase64 = Convert.ToBase64String(aesAlgorithm.Key);
                return keyBase64;
            }
        }
    }
}

