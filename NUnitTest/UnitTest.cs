using CryptoUtility;
using NUnit.Framework;
using System.Security.Cryptography;
using System.Text;

namespace Tests
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        [TestCase("要加密的字符串", "accbec399cb73bf6", "cbdabf4eaccbec399cb73bf63748882f")]
        public void TestMD5(string plainText, string cipherText16Bit, string cipherText)
        {
            MD5Utility md5Utility = new MD5Utility();
            Assert.AreEqual(cipherText16Bit, md5Utility.Encrypt16Bit(plainText));
            Assert.AreEqual(cipherText, md5Utility.Encrypt(plainText));
        }

        [TestCase(PaddingMode.PKCS7, "BPPe6PBNNdyPhdVF", "要加密的字符串", "Et/VmH7VhrHSO1EPtHVu9ccK3paKZYn6eWKXx7JF10g=")]
        [TestCase(PaddingMode.Zeros, "BPPe6PBNNdyPhdVF", "要加密的字符串", "Et/VmH7VhrHSO1EPtHVu9cXKFnOL8WevZE6J/4I4UkU=")]
        public void TestAES(PaddingMode paddingMode, string key, string plainText, string cipherText)
        {
            AESUtility aesUtility = new AESUtility(CipherMode.ECB, paddingMode, Encoding.UTF8);
            var result = aesUtility.Encrypt(plainText, key);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, aesUtility.Decrypt(result, key));
        }

        [TestCase(PaddingMode.PKCS7, "BPPe6PBNNdyPhdVF", "DPZGgSKNRaBItkWY", "要加密的字符串", "695alsHHmIpyEV+7oqE5j2xFmn7/aewDl1Qc0EqRFv0=")]
        [TestCase(PaddingMode.Zeros, "BPPe6PBNNdyPhdVF", "DPZGgSKNRaBItkWY", "要加密的字符串", "695alsHHmIpyEV+7oqE5jzg4kdST7Yu/diNFGA1IDAQ=")]
        public void TestAESWithVector(PaddingMode paddingMode, string key, string vector, string plainText, string cipherText)
        {
            AESUtility aesUtility = new AESUtility(CipherMode.CBC, paddingMode, Encoding.UTF8);
            var result = aesUtility.Encrypt(plainText, key, vector);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, aesUtility.Decrypt(result, key, vector));
        }

        [TestCase(PaddingMode.PKCS7, "BPPe6PBNNdyPhdVF", "要加密的字符串", "tqu+LUFsBnKiLf6oizK9US9KhXxZcann")]
        [TestCase(PaddingMode.Zeros, "BPPe6PBNNdyPhdVF", "要加密的字符串", "tqu+LUFsBnKiLf6oizK9UTDUZdbu76/w")]
        public void TestDES(PaddingMode paddingMode, string key, string plainText, string cipherText)
        {
            DESUtility desUtility = new DESUtility(CipherMode.ECB, paddingMode, Encoding.UTF8);
            var result = desUtility.Encrypt(plainText, key);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, desUtility.Decrypt(result, key));
        }

        [TestCase(PaddingMode.PKCS7, "BPPe6PBNNdyPhdVF", "DPZGgSKNRaBItkWY", "要加密的字符串", "cys2KmLpUMlPV7cQWeLp6LcMNiBZBHPS")]
        [TestCase(PaddingMode.Zeros, "BPPe6PBNNdyPhdVF", "DPZGgSKNRaBItkWY", "要加密的字符串", "cys2KmLpUMlPV7cQWeLp6GFUCrJGpfBe")]
        public void TestDESWithVector(PaddingMode paddingMode, string key, string vector, string plainText, string cipherText)
        {
            DESUtility desUtility = new DESUtility(CipherMode.CBC, paddingMode, Encoding.UTF8);
            var result = desUtility.Encrypt(plainText, key, vector);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, desUtility.Decrypt(result, key, vector));
        }

        [TestCase(PaddingMode.PKCS7, "QdWIxIwx49nFGdR6cXwu5F7Q", "要加密的字符串", "AS2g1F6X+BfHfr/7bCLFM33mN6Ako7Zw")]
        [TestCase(PaddingMode.Zeros, "QdWIxIwx49nFGdR6cXwu5F7Q", "要加密的字符串", "AS2g1F6X+BfHfr/7bCLFM/hG3FAO4yg7")]
        public void TestTripleDES(PaddingMode paddingMode, string key, string plainText, string cipherText)
        {
            TripleDESUtility tripleDESUtility = new TripleDESUtility(CipherMode.ECB, paddingMode, Encoding.UTF8);
            var result = tripleDESUtility.Encrypt(plainText, key);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, tripleDESUtility.Decrypt(result, key));
        }

        [TestCase(PaddingMode.PKCS7, "QdWIxIwx49nFGdR6cXwu5F7Q", "DPZGgSKNRaBItkWY", "要加密的字符串", "xN6B3my/Oe+Essm6yUDFQ5Luqp4D52+k")]
        [TestCase(PaddingMode.Zeros, "QdWIxIwx49nFGdR6cXwu5F7Q", "DPZGgSKNRaBItkWY", "要加密的字符串", "xN6B3my/Oe+Essm6yUDFQ4nij0GmKaPr")]
        public void TestTripleDESWithVector(PaddingMode paddingMode, string key, string vector, string plainText, string cipherText)
        {
            TripleDESUtility tripleDESUtility = new TripleDESUtility(CipherMode.CBC, paddingMode, Encoding.UTF8);
            var result = tripleDESUtility.Encrypt(plainText, key, vector);
            Assert.AreEqual(cipherText, result);
            Assert.AreEqual(plainText, tripleDESUtility.Decrypt(result, key, vector));
        }

        [TestCase(
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8E1PbfgAgrWJIufMSu55wEmGxmN5JSJ4J49D9sw9ok+yj14CNZHfgl9NhuqaHGWJd3tFh9BcbSrAtW7xlJM5n2diVCdX9E29T0Cf9EnWJhu9DxEH6bzbOMT6OR9EQo/9I+gNYvIUt/dCHNti6G4gxp4pxyiWtxdQu9HDoFQ2f9wIDAQAB",
            "MIICXAIBAAKBgQC8E1PbfgAgrWJIufMSu55wEmGxmN5JSJ4J49D9sw9ok+yj14CNZHfgl9NhuqaHGWJd3tFh9BcbSrAtW7xlJM5n2diVCdX9E29T0Cf9EnWJhu9DxEH6bzbOMT6OR9EQo/9I+gNYvIUt/dCHNti6G4gxp4pxyiWtxdQu9HDoFQ2f9wIDAQABAoGAZa2xTV3uZbw3AYh+UGdcfcyCQoiZzFbVEhW3PCFdODWY3u84Ebj6UlLitdg6BZoEoyk+W82h3GBhpPQOg0QFzhP4Hhc8BkuEJWZlTvNxVke3+dKWfPX+/+TZ0zcMtM44Jp+jSXPSulFLvkvod4de+AxRK65UBgA3cAZ+yq737KkCQQDkQshWFiYmZzQPRjiqQ8NtkCk0hoR24mtcIPdjifTevCfuZkfTWP+akiI4HE8FL1x4fyKwXFpx8SIFkh2cF+ftAkEA0u5f0G0BOA5huyeCuTeMgXjQkfhJaHWjQvxWi0MzXJqZjs+2/44nyJe9Cbo3+gNRcyfVo7+n2P7jTSPmU+si8wJAHt9peTtFrawHvokg4OaJaCg3aoNHJ004eB19WFkwZW/NdtEepddDuwRI3I33ohvlxeZsKq5TDVYv49D/cD1LgQJBAIVp2JiQGbFHB3HE794O0IQj0mhBTs0PexAnYuX6v0XXU0ENCIZjd65cq2i3rCgqaR4ZF/vWgWey8DoedtSlaRkCQBHzcIJnbpEWrYw7B2yPPQApwL9QQky1/dLMROI+Ea8qml7bwzMyXHGHQVUSG7drVfuTnl45bb4cFKORsCZFwf0=",
            "要加密的字符串",
            "xN6B3my/Oe+Essm6yUDFQ5Luqp4D52+k","")]
        public void TestRSA(string publicKey, string privateKey, string plainText, string cipherText, string sign)
        {
            RSAUtility rsaUtility = new RSAUtility(HashAlgorithmName.SHA1, Encoding.UTF8, publicKey, privateKey);
            var result = rsaUtility.Sign(plainText);
        }
    }
}