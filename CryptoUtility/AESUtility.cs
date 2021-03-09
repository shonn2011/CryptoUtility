using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility
{
    public class AESUtility
    {
        private readonly Encoding _encoding;

        private readonly int _keySize;

        private readonly CipherMode _cipherMode;

        private readonly PaddingMode _paddingMode;

        /// <summary>
        /// AES加密解密工具类
        /// 加密模式=ECB；
        /// 填充模式=PKCS7；
        /// 密钥大小=128；
        /// 编码格式=UTF-8；
        /// </summary>
        public AESUtility()
        {
            _cipherMode = CipherMode.ECB;
            _paddingMode = PaddingMode.PKCS7;
            _keySize = 128;
            _encoding = Encoding.UTF8;
        }

        /// <summary>
        /// AES加密解密工具类
        /// 密钥大小=128；
        /// </summary>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <param name="encoding">编码格式</param>
        public AESUtility(CipherMode cipherMode, PaddingMode paddingMode, Encoding encoding)
        {
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _keySize = 128;
            _encoding = encoding;
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new Exception("PlainText is null or empty");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Key is null or empty");
            }

            byte[] plainBytes = _encoding.GetBytes(plainText);
            byte[] keyBytes = _encoding.GetBytes(key);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;
                aes.KeySize = _keySize;
                aes.Key = keyBytes;

                string cipherText = string.Empty;
                using (ICryptoTransform cryptoTransform = aes.CreateEncryptor())
                {
                    byte[] cipherBytes = cryptoTransform.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    cipherText = Convert.ToBase64String(cipherBytes);
                }
                return cipherText;
            }
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="vector">向量</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText, string key, string vector)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new Exception("PlainText is null or empty");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Key is null or empty");
            }

            byte[] plainBytes = _encoding.GetBytes(plainText);
            byte[] keyBytes = _encoding.GetBytes(key);
            byte[] vectorBytes = _encoding.GetBytes(vector);

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = _keySize;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;

                string cipherText = string.Empty;
                using (ICryptoTransform cryptoTransform = aes.CreateEncryptor(keyBytes, vectorBytes))
                {
                    byte[] cipherBytes = cryptoTransform.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    cipherText = Convert.ToBase64String(cipherBytes);
                }
                return cipherText;
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="key">密钥</param>
        /// <returns>明文</returns>
        public string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                throw new Exception("CipherText is null or empty");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Key is null or empty");
            }

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = _encoding.GetBytes(key);

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = _keySize;
                aes.Key = keyBytes;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;

                string plainText = string.Empty;
                using (ICryptoTransform cryptoTransform = aes.CreateDecryptor())
                {
                    byte[] plainBytes = cryptoTransform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    plainText = _encoding.GetString(plainBytes).Trim('\0');
                }
                return plainText;
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="vector">向量</param>
        /// <returns>明文</returns>
        public string Decrypt(string cipherText, string key, string vector)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                throw new Exception("CipherText is null or empty");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("Key is null or empty");
            }

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = _encoding.GetBytes(key);
            byte[] vectorBytes = _encoding.GetBytes(vector);

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = _keySize;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;

                string plainText = string.Empty;
                using (ICryptoTransform cryptoTransform = aes.CreateDecryptor(keyBytes, vectorBytes))
                {
                    byte[] plainBytes = cryptoTransform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    plainText = _encoding.GetString(plainBytes).Trim('\0');
                }
                return plainText;
            }
        }
    }
}
