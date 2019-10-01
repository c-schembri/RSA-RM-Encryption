using System.IO;
using System.Security.Cryptography;

namespace Encryption
{
    public static class ClientEncryption
    {
        /// <summary>
        /// Returns the current session key as hexadecimally encoded string.
        /// </summary>
        public static string SessionKey => rijndaelManaged.Key.ToHexString();
        
        /// <summary>
        /// Returns the current initialisation vector ('IV') as hexadecimally encoded string.
        /// </summary>
        public static string InitialisationVector => rijndaelManaged.IV.ToHexString();
        
        /// <summary>
        /// The class by which symmetric encryption is handled, i.e., how keys and IVs are generated.
        /// </summary>
        private static readonly RijndaelManaged rijndaelManaged;

        /// <summary>
        /// The server's public key for asymmetric encryption. 
        /// </summary>
        /// <remarks>This key is used to encrypt the session key that is (eventually) sent to the server.</remarks>
        private static readonly RSAParameters publicKey;

        /// <summary>
        /// Initialises the server's public RSA key and RijndaelManaged state.
        /// </summary>
        static ClientEncryption()
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.FromXmlString(RsaKeys.Public_Key);
                publicKey = rsaCryptoServiceProvider.ExportParameters(false);
            }
            rijndaelManaged = new RijndaelManaged();
            rijndaelManaged.GenerateKey();
            rijndaelManaged.GenerateIV();
        }

        /// <summary>
        /// Encrypts the RijndaelManaged key, i.e., the session key, by virtue of RSACryptoServiceProvider, returning the cipher as byte[].
        /// </summary>
        /// <param name="generateNewKey">Generates a new session key after encryption if true.</param>
        public static byte[] RsaEncryptCipher(bool generateNewKey = false)
        {
            using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
            {
                rsaCryptoServiceProvider.ImportParameters(publicKey);
                byte[] encryptedSessionKey = rsaCryptoServiceProvider.Encrypt(rijndaelManaged.Key, false);
                // Remember: if a new session key is generated, it _must_ be sent to the server so as to be able to decrypt RijndaelManaged encrypted ciphers.
                if (generateNewKey) rijndaelManaged.GenerateKey();
                return encryptedSessionKey;
            }
        }

        /// <summary>
        /// Encrypts the passed plain text, by virtue of RijndaelManaged, i.e., the session key, returning the cipher as byte[].
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="sessionKey">The RijndaelManaged key with which the plain text is encrypted.</param>
        public static byte[] EncryptPlainText(string plainText, byte[] sessionKey)
        {
            try
            {
                var encryptor = rijndaelManaged.CreateEncryptor(sessionKey, rijndaelManaged.IV);
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
            finally
            {
                // For increased security, generate a new IV with every message.
                // Be aware, however, that this initialisation vector is required by the server for each message that is encrypted by the session key (be sure not to encrypt the IV!).
                rijndaelManaged.GenerateIV();
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
            // It is possible to streamline this process by simply storing the RijndaelManaged key state, because (most of the time) clients do not need to change their session keys.
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
