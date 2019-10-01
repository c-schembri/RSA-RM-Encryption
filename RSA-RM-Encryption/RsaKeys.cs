namespace Encryption
{
    internal static class RsaKeys
    {
        /// <summary>
        /// The server's public RSA key, in XML format.
        /// </summary>
        /// <remarks>The client _must_ know this public key, but it is not necessary for the server to know it. Obviously, generate your own key(s).</remarks>
        internal const string Public_Key = @"<RSAKeyValue><Modulus>nPcJzyGcYsBQrghA3zxvQNehcKNpWClzyWXHt5INpQCJZYE2GvI8oMTudRm6Mh7j2L9x0CkioEwNLaxN8kTRsPOmhLbv0rvasXunU/X9fDNSBHCL5oPdzMZG2xoD2qq4nxk5FxyH/vcW/jgz6rSQyDaOSaHV6NN0gAnaDoh6/kc=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        /// <summary>
        /// The server's private RSA key, in XML format.
        /// </summary>
        /// <remarks>The server _must_ know this private key; the client _must not_ know this private key. Obviously, generate your own key(s).</remarks>
        internal const string Private_Key = @"<RSAKeyValue><Modulus>nPcJzyGcYsBQrghA3zxvQNehcKNpWClzyWXHt5INpQCJZYE2GvI8oMTudRm6Mh7j2L9x0CkioEwNLaxN8kTRsPOmhLbv0rvasXunU/X9fDNSBHCL5oPdzMZG2xoD2qq4nxk5FxyH/vcW/jgz6rSQyDaOSaHV6NN0gAnaDoh6/kc=</Modulus><Exponent>AQAB</Exponent><P>/qxZVhHMpbzXG9SjiNaOQ6KootbXIX0pl6dMSgHJiOR8G010isB2AcX5oGOJVC1K3Mr0ezBrjPPbyg3xeVTl2Q==</P><Q>nchg4BVBux853dqtbce0gDX2RtUjuToAP2aafk998/e2dSy9AcEnu/p5W1dCfC+i7HezRqkrmFHqi+w5WtXRHw==</Q><DP>OanehH19P921Owj3iklCZxASbOSGS3/ihgMMZAlpj4RkkW4FQFF5pscj0WwYMSYcOEf/+VCqWXzxvBtSHK3baQ==</DP><DQ>RfBeULXbbxCGW/rkyTauoe5JflhX/3DgTzox3S9rS0tQS1xLY421CTQbuwtQ4y9SbrMYeofeVSRqbR+GxObmTQ==</DQ><InverseQ>XCFNpBUr0igudZgJvjj3734GUZBJcqv9FoSSknlShBYLxYc87idGPEqh+i5FRCZ7V5jMpyFCMfBThlMrmvfdgg==</InverseQ><D>RoA/C6XRFBnFIyXZ3WrLnZg8jtcW7d5Qf1kTx0P2lPIUxF6w6pF64csSP856byCoviXe/Nw9DTqbgLQvnm2CsPq9BnOpuWgVjgpSVyZUovuKzysxUCv9iplgP3yidLDYnHcfJwT1mJ2kXY2f6VweXjFREzgDoLxXiFleamwG0sE=</D></RSAKeyValue>";
    }
}