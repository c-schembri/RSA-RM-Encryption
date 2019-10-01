# RSA-RM-Encryption
A complete encryption-decryption, asymmetrical (RSA)-symmetrical (RM) suite completely written in C#.

## What the repository contains
The repository is composed of three major components: the library, unit tests, and an example project.
These three components are more than sufficient in understanding the source code, as well as verifying its success.

## Further information & resources
The asymmetrical encryption used is Microsoft's RSACryptoServiceProvider (hence RSA) as contained in System.Security.Cryptography (https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8).

The symmetrical encryption used is Microsoft's RijndaelManaged (hence RM) as contained in System.Security.Cryptography (https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?view=netframework-4.8).

It is entirely (and quite easy) possible to convert this program into a .NET Core program (especially with the further XML -cryptographic implementations contained in 3.0, thus allowing it to run on virtually any system.

The supplied (successful) unit tests cover all possible operations that can be performed via the library function.

## A final note
Remember to change the RSA public and private key.
