using System;
using Encryption;

namespace ExampleProgram
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            // T0
            // -- CLIENT --
            // Simulating a client-server relationship, the first step required is for the client to
            // generate a session key and encrypt it by virtue of the server's public key.
            // (Because the encryption libraries are static, this first step is automatically completed.)
            string sessionKey = ClientEncryption.RsaEncryptCipher().ToHexString();
            Console.WriteLine($"Client session key is: {sessionKey}");
            // At this point, the client sends this session key to the server.
            // -- END CLIENT --
            
            // T1
            // -- SERVER --
            // Once the server receives this session key, it must decrypt it by virtue of its private key.
            // Now actual messages can be sent.
            byte[] decryptedSessionKey = ServerEncryption.RsaDecryptCipher(sessionKey);
            Console.WriteLine($"Client session key length is: {decryptedSessionKey.Length}");
            // -- END SERVER --

            while (true)
            {
                // T2
                // At this stage, your program will send whatever information to the server or client.
                Console.WriteLine("Please enter some plain text: ");
                string plainText = Console.ReadLine();
                
                // T3
                // -- CLIENT --
                // Now the session key can be itself used for encryption.
                // Hex string is convenient for sending data because its characters are wide-spread.
                string initialisationVector = ClientEncryption.InitialisationVector;
                Console.WriteLine($"The current initialisation vector is: {initialisationVector}");
                
                // Encrypt the plain text.
                string cipher = ClientEncryption.EncryptPlainText(plainText, sessionKey.ToByteArray()).ToHexString();
                Console.WriteLine($"Your plain text ({plainText}) encrypted is: {cipher}");
                
                // Then send the cipher to the server.
                // Remember to send the initialisation vector, if using it, along with the message, like so:
                string message = $"{initialisationVector}{cipher}";
                Console.WriteLine($"The complete message (IV and cipher) is: {message}");
                // -- END CLIENT --
            
                // T4
                // -- SERVER --
                // The server then receives an encrypted (hex) string. However, it first needs to organise the
                // information before decrypting it, by discerning the IV and cipher (i.e., the actual message).
                // Of course, this step is not necessary if you decide not to utilise initialisation vectors.
                byte[] initialisationVectorBytes = ServerEncryption.ParseIvFromMessage(message);
                Console.WriteLine($"The length of the initialisation vector is: {initialisationVectorBytes.Length}");
                byte[] decipherBytes = ServerEncryption.ParseCipherFromMessage(message);
                Console.WriteLine($"The length of the (de)cipher is: {decipherBytes.Length}");
                
                // All that is remaining to do is to decrypt the cipher.
                string decipher = ServerEncryption.DecryptCipher(decipherBytes, decryptedSessionKey, initialisationVectorBytes);
                Console.WriteLine($"The deciphered message is: {decipher}");
                // Decryption complete.
                // -- END SERVER --
            }
        }
    }
}