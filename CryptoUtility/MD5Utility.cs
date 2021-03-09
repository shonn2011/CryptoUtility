using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility
{
    public class MD5Utility
    {
        private readonly Encoding _encoding;

        /// <summary>
        /// MD5加密工具类
        /// 编码格式：UTF-8
        /// </summary>
        public MD5Utility()
        {
            _encoding = Encoding.UTF8;
        }

        /// <summary>
        /// MD5加密工具类
        /// </summary>
        /// <param name="encoding">编码格式</param>
        public MD5Utility(Encoding encoding)
        {
            _encoding = encoding;
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] bytes = md5.ComputeHash(_encoding.GetBytes(plainText));
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    stringBuilder.Append(b.ToString("x2"));
                }
                return stringBuilder.ToString();
            }
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="stream">数据流</param>
        /// <returns>密文</returns>
        public string Encrypt(Stream stream)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] bytes = md5.ComputeHash(stream);
                StringBuilder stringBuilder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    stringBuilder.Append(b.ToString("x2"));
                }
                return stringBuilder.ToString();
            }
        }

        /// <summary>
        /// 16位加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns>密文</returns>
        public string Encrypt16Bit(string plainText)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            string cipherText = BitConverter.ToString(md5.ComputeHash(_encoding.GetBytes(plainText)), 4, 8);
            cipherText = cipherText.Replace("-", "").ToLower();
            return cipherText;
        }
    }
}
