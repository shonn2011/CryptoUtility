using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility
{
    public class DESUtility
    {
        private readonly Encoding _encoding;

        private readonly CipherMode _cipherMode;

        private readonly PaddingMode _paddingMode;

        /// <summary>
        /// DES加密解密工具类
        /// 加密模式=ECB；
        /// 填充模式=PKCS7；
        /// 编码格式=UTF-8；
        /// </summary>
        public DESUtility()
        {
            _cipherMode = CipherMode.ECB;
            _paddingMode = PaddingMode.PKCS7;
            _encoding = Encoding.UTF8;
        }

        /// <summary>
        /// DES加密解密工具类
        /// </summary>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <param name="encoding">编码格式</param>
        public DESUtility(CipherMode cipherMode, PaddingMode paddingMode, Encoding encoding)
        {
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
            _encoding = encoding;
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥(长度为8位)</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new Exception("PlainText is null or empty");
            }
            if (string.IsNullOrEmpty(key) || key.Length < 8)
            {
                throw new Exception("The length of the key must be 8 bits");
            }
            key = key.Length > 8 ? key.Substring(0, 8) : key;

            byte[] plainBytes = _encoding.GetBytes(plainText);
            byte[] keyBytes = _encoding.GetBytes(key);

            using (DES des = DES.Create())
            {
                des.Mode = _cipherMode;
                des.Padding = _paddingMode;
                des.Key = keyBytes;

                string cipherText = string.Empty;
                using (ICryptoTransform cryptoTransform = des.CreateEncryptor())
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
            if (string.IsNullOrEmpty(key) || key.Length < 8)
            {
                throw new Exception("The length of the key must be 8 bits");
            }
            if (string.IsNullOrEmpty(vector) || vector.Length < 8)
            {
                throw new Exception("The length of the vector must be 8 bits");
            }
            key = key.Length > 8 ? key.Substring(0, 8) : key;
            vector = vector.Length > 8 ? vector.Substring(0, 8) : vector;

            byte[] plainBytes = _encoding.GetBytes(plainText);
            byte[] keyBytes = _encoding.GetBytes(key);
            byte[] vectorBytes = _encoding.GetBytes(vector);

            using (DES des = DES.Create())
            {
                des.Mode = _cipherMode;
                des.Padding = _paddingMode;

                string cipherText = string.Empty;
                using (ICryptoTransform cryptoTransform = des.CreateEncryptor(keyBytes, vectorBytes))
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
                throw new Exception("PlainText is null or empty");
            }
            if (string.IsNullOrEmpty(key) || key.Length < 8)
            {
                throw new Exception("The length of the key must be 8 bits");
            }
            key = key.Length > 8 ? key.Substring(0, 8) : key;

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = _encoding.GetBytes(key);

            using (DES des = DES.Create())
            {
                des.Mode = _cipherMode;
                des.Padding = _paddingMode;
                des.Key = keyBytes;

                string plainText = string.Empty;
                using (ICryptoTransform cryptoTransform = des.CreateDecryptor())
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
                throw new Exception("PlainText is null or empty");
            }
            if (string.IsNullOrEmpty(key) || key.Length < 8)
            {
                throw new Exception("The length of the key must be 8 bits");
            }
            if (string.IsNullOrEmpty(vector) || vector.Length < 8)
            {
                throw new Exception("The length of the vector must be 8 bits");
            }
            key = key.Length > 8 ? key.Substring(0, 8) : key;
            vector = vector.Length > 8 ? vector.Substring(0, 8) : vector;

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] keyBytes = _encoding.GetBytes(key);
            byte[] vectorBytes = _encoding.GetBytes(vector);

            using (DES des = DES.Create())
            {
                des.Mode = _cipherMode;
                des.Padding = _paddingMode;

                string plainText = string.Empty;
                using (ICryptoTransform cryptoTransform = des.CreateDecryptor(keyBytes, vectorBytes))
                {
                    byte[] plainBytes = cryptoTransform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    plainText = _encoding.GetString(plainBytes).Trim('\0');
                }
                return plainText;
            }
        }
    }
}
