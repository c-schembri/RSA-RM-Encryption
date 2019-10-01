using System.IO;
using System.Security.Cryptography;

namespace Encryption
{
    public static class ServerEncryption
    {
        /// <summary>
        /// The server's private RSA key for asymmetric decryption.
        /// </summary>
        /// <remarks>This key is used to decrypt the session key that is sent by the client(s).</remarks>
        private static readonly RSAParameters privateKey;

        /// <summary>
        /// Intialises the server's private RSA key.
        /// </summary>
        static ServerEncryption()
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.FromXmlString(RsaKeys.Private_Key);
                privateKey = rsaCryptoServiceProvider.ExportParameters(true);
            }
        }
        
        /// <summary>
        /// Decrypts the passed cipher, by virtue of RSACryptoServiceProvider, returning the plain text as byte[].
        /// </summary>
        /// <param name="cipher">The cipher to decrypt.</param>
        public static byte[] RsaDecryptCipher(string cipher)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.ImportParameters(privateKey);
                byte[] cipherBytes = cipher.ToByteArray();
                byte[] plaintextBytes = rsaCryptoServiceProvider.Decrypt(cipherBytes, false);

                return plaintextBytes;
            }
        }

        /// <summary>
        /// Encrypts the passed plain text, by virtue of RijndaelManaged, i.e., the session key, returning the cipher as byte[].
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="sessionKey">The RijndaelManaged key with which the plain text is encrypted.</param>
        /// <param name="initialisationVector">The RijndaelManaged initialisation vector with which the plain text is encrypted.</param>
        public static byte[] EncryptPlainText(string plainText, byte[] sessionKey, out string initialisationVector)
        {
            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Key = sessionKey;
                rijndaelManaged.GenerateIV();
                var encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                initialisationVector = rijndaelManaged.IV.ToHexString();
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts the passed byte[] cipher, by virtue of RijndaelManaged, i.e., the session key, returning the plain text as string.
        /// </summary>
        /// <param name="cipher">The cipher to decrypt.</param>
        /// <param name="sessionKey">The RijndaelManaged key with which the plain text is decrypted.</param>
        /// <param name="initialisationVector">The RijndaelManaged initialisation vector with which the plain text is decrypted.</param>
        public static string DecryptCipher(byte[] cipher, byte[] sessionKey, byte[] initialisationVector)
        {
            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Key = sessionKey;
                rijndaelManaged.IV = initialisationVector;
                var decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                using (var memoryStream = new MemoryStream(cipher))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }

            }
        }

        /// <summary>
        /// Returns the first 16 bytes of the passed hexadecimally encoded string, thereby returning the RijndaelManaged initialisation vector (IV).
        /// </summary>
        /// <param name="hexString">The hexadecimally encoded string to parse.</param>
        public static byte[] ParseIvFromMessage(string hexString)
        {
            // Each hex byte is 2 characters. Thus, 16 bytes = 32 characters.
            const int iv_length = 32;
            return hexString.Substring(0, iv_length).ToByteArray();
        }

        /// <summary>
        /// Returns all characters starting from the 17th byte (bypassing the IV), thereby returning the cipher.
        /// </summary>
        /// <param name="hexString">The hexadecimally encoded string to parse.</param>
        public static byte[] ParseCipherFromMessage(string hexString)
        {
            // Each hex byte is 2 characters. Thus, 16 bytes = 32 characters.
            const int cipher_starting_index = 32;
            return hexString.Substring(cipher_starting_index).ToByteArray();
        }
    }
}
