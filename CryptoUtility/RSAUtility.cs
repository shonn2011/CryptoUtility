using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility
{
    public class RSAUtility
    {
        private readonly RSA _privateKeyRSA;
        private readonly RSA _publicKeyRSA;
        private readonly HashAlgorithmName _hashAlgorithmName;
        private readonly Encoding _encoding;

        /// <summary>
        /// RSA工具类
        /// </summary>
        /// <param name="hashAlgorithmName"></param>
        /// <param name="encoding"></param>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        public RSAUtility(HashAlgorithmName hashAlgorithmName, Encoding encoding, string privateKey, string publicKey = null)
        {
            _hashAlgorithmName = hashAlgorithmName;
            _encoding = encoding;
            if (!string.IsNullOrEmpty(privateKey))
            {
                _privateKeyRSA = CreateRSAFromPrivateKey(privateKey);
            }
            if (!string.IsNullOrEmpty(publicKey))
            {
                _publicKeyRSA = CreateRSAFromPublicKey(publicKey);
            }
        }

        /// <summary>
        /// 私钥签名
        /// </summary>
        /// <param name="data">数据字符串</param>
        /// <returns>签名字符串</returns>
        public string Sign(string data)
        {
            byte[] dataBytes = _encoding.GetBytes(data);
            var signatureBytes = _privateKeyRSA.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// 公钥验签
        /// </summary>
        /// <param name="data">数据字符串</param>
        /// <param name="sign">签名字符串</param>
        /// <returns>验证结果</returns>
        public bool Verify(string data, string sign)
        {
            byte[] dataBytes = _encoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);
            var verify = _publicKeyRSA.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            return verify;
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText)
        {
            if (_publicKeyRSA == null)
            {
                throw new Exception("PublicKey is null");
            }
            return Convert.ToBase64String(_publicKeyRSA.Encrypt(_encoding.GetBytes(plainText), RSAEncryptionPadding.Pkcs1));
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <returns>明文</returns>
        public string Decrypt(string cipherText)
        {
            if (_privateKeyRSA == null)
            {
                throw new Exception("PrivateKey is null");
            }
            return Encoding.UTF8.GetString(_privateKeyRSA.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1));
        }

        /// <summary>
        /// 使用公钥创建RSA实例
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns>RSA实例</returns>
        private RSA CreateRSAFromPublicKey(string publicKey)
        {
            byte[] seqOId = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] x509Key = Convert.FromBase64String(publicKey);
            using (MemoryStream memoryStream = new MemoryStream(x509Key))
            {
                using (BinaryReader binaryReader = new BinaryReader(memoryStream))
                {
                    byte bt = 0;
                    ushort twobytes = 0;
                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130)
                    {
                        binaryReader.ReadByte();
                    }
                    else if (twobytes == 0x8230)
                    {
                        binaryReader.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    byte[] seq = binaryReader.ReadBytes(15);
                    if (!CompareBytearrays(seq, seqOId))
                    {
                        return null;
                    }

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8103)
                    {
                        binaryReader.ReadByte();
                    }
                    else if (twobytes == 0x8203)
                    {
                        binaryReader.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    bt = binaryReader.ReadByte();
                    if (bt != 0x00)
                    {
                        return null;
                    }

                    twobytes = binaryReader.ReadUInt16();
                    if (twobytes == 0x8130)
                    {
                        binaryReader.ReadByte();
                    }
                    else if (twobytes == 0x8230)
                    {
                        binaryReader.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    twobytes = binaryReader.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102)
                    {
                        lowbyte = binaryReader.ReadByte();
                    }
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binaryReader.ReadByte();
                        lowbyte = binaryReader.ReadByte();
                    }
                    else
                    {
                        return null;
                    }
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binaryReader.PeekChar();
                    if (firstbyte == 0x00)
                    {
                        binaryReader.ReadByte();
                        modsize -= 1;
                    }

                    byte[] modulus = binaryReader.ReadBytes(modsize);

                    if (binaryReader.ReadByte() != 0x02)
                    {
                        return null;
                    }
                    int expbytes = (int)binaryReader.ReadByte();
                    byte[] exponent = binaryReader.ReadBytes(expbytes);

                    var rsa = RSA.Create();
                    RSAParameters rsaParameters = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaParameters);
                    return rsa;
                }
            }
        }

        /// <summary>
        /// 使用私钥创建RSA实例
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>RSA实例</returns>
        private RSA CreateRSAFromPrivateKey(string privateKey)
        {
            byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
            RSA rsa = RSA.Create();
            RSAParameters rsaParameters = new RSAParameters();
            using (BinaryReader binaryReader = new BinaryReader(new MemoryStream(privateKeyBytes)))
            {
                byte b = 0;
                ushort twobytes = 0;
                twobytes = binaryReader.ReadUInt16();
                if (twobytes == 0x8130)
                {
                    binaryReader.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    binaryReader.ReadInt16();
                }
                else
                {
                    throw new Exception("Unexpected value read BinaryReader.ReadUInt16()");
                }

                twobytes = binaryReader.ReadUInt16();
                if (twobytes != 0x0102)
                {
                    throw new Exception("Unexpected version");
                }

                b = binaryReader.ReadByte();
                if (b != 0x00)
                {
                    throw new Exception("Unexpected value read BinaryReader.ReadByte()");
                }
                rsaParameters.Modulus = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Exponent = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.D = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.P = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.Q = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DP = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.DQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
                rsaParameters.InverseQ = binaryReader.ReadBytes(GetIntegerSize(binaryReader));
            }
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        /// <summary>
        /// 导入密钥算法
        /// </summary>
        /// <param name="binaryReader"></param>
        /// <returns></returns>
        private int GetIntegerSize(BinaryReader binaryReader)
        {
            byte bt = binaryReader.ReadByte();
            if (bt != 0x02)
            {
                return 0;
            }
            bt = binaryReader.ReadByte();

            int count;
            if (bt == 0x81)
            {
                count = binaryReader.ReadByte();
            }
            else
            if (bt == 0x82)
            {
                var highbyte = binaryReader.ReadByte();
                var lowbyte = binaryReader.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binaryReader.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binaryReader.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        private bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
