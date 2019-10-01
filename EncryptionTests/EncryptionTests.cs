using System;
using Encryption;
using System.Linq;
using System.Text;
using NUnit.Framework;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace UnitTests
{
    [TestFixture]
    public class EncryptionTests
    {
        /// <summary>
        /// Generates multiple session keys: fails if any duplicate keys are created.
        /// </summary>
        [Test]
        public void CheckClientEncryption_RSA()
        {
            GenerateClientSessionKeys(out _, out var encryptedSessionKeys);
            if (encryptedSessionKeys.Count != encryptedSessionKeys.Distinct().Count())
            {
                throw new Exception("Duplicate session keys found.");
            }
        }
        
        /// <summary>
        /// Checks server decryption of RSA encrypted (by public key) session keys (by private key): fails if any decrypted session keys do not match their unencrypted state.
        /// </summary>
        [Test]
        public void CheckServerDecryption_RSA()
        {
            GenerateClientSessionKeys(out var unencryptedSessionKeys, out var encryptedSessionKeys);
            List<byte[]> decryptedSessionKeys = new List<byte[]>();

            Assert.That(encryptedSessionKeys.Count > 0);
            foreach (string key in encryptedSessionKeys)
            {
                decryptedSessionKeys.Add(ServerEncryption.RsaDecryptCipher(key));
            }
            Assert.AreEqual(encryptedSessionKeys.Count, decryptedSessionKeys.Count);

            // Ensuring that there is equivalence between unencrypted and decrypted session keys.
            for (int i = 0; i < decryptedSessionKeys.Count; i++)
            { 
                Assert.AreEqual(decryptedSessionKeys[i].ToHexString(), unencryptedSessionKeys[i]);
            }
        }

        /// <summary>
        /// Checks server decryption of RM encrypted cipher by virtue of session keys and initialisation vectors: fails if any client plain texts do not match the server deciphered texts.
        /// </summary>
        [Test]
        public void CheckServerDecryption_RM()
        {
            GenerateClientSessionKeys(out var unencryptedSessionKeys, out var encryptedSessionKeys);
            List<byte[]> decryptedSessionKeys = new List<byte[]>();
            foreach (string key in encryptedSessionKeys)
            {
                decryptedSessionKeys.Add(ServerEncryption.RsaDecryptCipher(key));
            }

            Assert.That(decryptedSessionKeys.Count > 0);
            for (int i = 0; i < decryptedSessionKeys.Count; i++)
            {
                string plainText = GenerateRandomString(24);
                Assert.That(plainText.Length == 24);
                
                // Encrypt and prepare the message [ClientEncryption_RM].
                string initialisationVector = ClientEncryption.InitialisationVector;
                string cipher = ClientEncryption.EncryptPlainText(plainText, unencryptedSessionKeys[i].ToByteArray()).ToHexString();
                string message = $"{initialisationVector}{cipher}";
            
                // Decrypt the message.
                byte[] initialisationVectorBytes = ServerEncryption.ParseIvFromMessage(message);
                byte[] cipherBytes = ServerEncryption.ParseCipherFromMessage(message);
                string decipher = ServerEncryption.DecryptCipher(cipherBytes, decryptedSessionKeys[i], initialisationVectorBytes);
         
                Assert.AreEqual(plainText, decipher);
            }
        }

        /// <summary>
        /// Checks server encryption of RM encrypted plain texts by virtue of session keys and initialisation vectors: fails if any server plain texts do not match the client deciphered texts.
        /// </summary>
        [Test]
        public void CheckServerEncryption_RM()
        {
            GenerateClientSessionKeys(out _, out var encryptedSessionKeys);
            List<byte[]> decryptedSessionKeys = new List<byte[]>();
            foreach (string key in encryptedSessionKeys)
            {
                decryptedSessionKeys.Add(ServerEncryption.RsaDecryptCipher(key));
            }

            Assert.That(decryptedSessionKeys.Count > 0);
            for (int i = 0; i < decryptedSessionKeys.Count; i++)
            {
                string plainText = GenerateRandomString(36);
                Assert.That(plainText.Length == 36);
                
                // Encrypt and prepare the message.
                string cipher = ServerEncryption.EncryptPlainText(plainText, decryptedSessionKeys[i], out string initialisationVector).ToHexString();
                string message = $"{initialisationVector}{cipher}";
                
                // Decrypt the message [ClientDecryption_RM]
                byte[] initialisationVectorBytes = ClientEncryption.ParseIvFromMessage(message);
                byte[] cipherBytes = ClientEncryption.ParseCipherFromMessage(message);
                string decipher = ClientEncryption.DecryptCipher(cipherBytes, decryptedSessionKeys[i], initialisationVectorBytes);
                
                Assert.AreEqual(plainText, decipher);
            }
        }
        
        /// <summary>
        /// Generates various sessions key states for the unit tests.
        /// </summary>
        private static void GenerateClientSessionKeys(out List<string> unencryptedSessionKeys, out List<string> encryptedSessionKeys)
        {
            unencryptedSessionKeys = new List<string>();
            encryptedSessionKeys = new List<string>();
            
            for (int i = 0; i < 1_000; i++)
            {
                unencryptedSessionKeys.Add(ClientEncryption.SessionKey);
                encryptedSessionKeys.Add(ClientEncryption.RsaEncryptCipher(true).ToHexString());
            }
        }
        
        /// <summary>
        /// Returns a properly random alphanumeric string, on the basis of the passed length, for the unit tests.
        /// </summary>
        private static string GenerateRandomString(int length)
        {
            char[] validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();
            byte[] accountIdBytes = new byte[length];

            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                rngCryptoServiceProvider.GetBytes(accountIdBytes);
            }

            var result = new StringBuilder(length);
            foreach (byte b in accountIdBytes)
            {
                result.Append(validChars[b % validChars.Length]);
            }

            return result.ToString();
        }
    }
}