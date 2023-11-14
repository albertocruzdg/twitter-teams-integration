using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TwitterTeamsIntegration.API;

public class Decryptor
{
    public X509Certificate2 Certificate { get; set; }


    public string Decrypt(string data, string dataSignature, string dataKey)
    {
        using var rsaPrivateKey = Certificate.GetRSAPrivateKey();

        if (rsaPrivateKey == null)
        {
            throw new Exception("Null key");
        }

        RSAParameters rsaParams = rsaPrivateKey.ExportParameters(true);

        // Create a new RSACryptoServiceProvider and import the parameters
        RSACryptoServiceProvider provider = new RSACryptoServiceProvider(rsaPrivateKey.KeySize);
        provider.ImportParameters(rsaParams);


        byte[] encryptedSymmetricKey = Convert.FromBase64String(dataKey);
        byte[] decryptedSymmetricKey = provider.Decrypt(encryptedSymmetricKey, fOAEP: true);

        byte[] encryptedPayload = Convert.FromBase64String(data);
        byte[] expectedSignature = Convert.FromBase64String(dataSignature);
        byte[] actualSignature;

        using (HMACSHA256 hmac = new HMACSHA256(decryptedSymmetricKey))
        {
            actualSignature = hmac.ComputeHash(encryptedPayload);
        }

        if (actualSignature.SequenceEqual(expectedSignature))
        {
            // Continue with decryption of the encryptedPayload.
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Key = decryptedSymmetricKey;
            aesProvider.Padding = PaddingMode.PKCS7;
            aesProvider.Mode = CipherMode.CBC;

            // Obtain the intialization vector from the symmetric key itself.
            int vectorSize = 16;
            byte[] iv = new byte[vectorSize];
            Array.Copy(decryptedSymmetricKey, iv, vectorSize);
            aesProvider.IV = iv;

            // Decrypt the resource data content.
            using (var decryptor = aesProvider.CreateDecryptor())
            {
                using (MemoryStream msDecrypt = new MemoryStream(encryptedPayload))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            var decryptedResourceData = srDecrypt.ReadToEnd();
                            return decryptedResourceData;
                        }
                    }
                }
            }

            // decryptedResourceData now contains a JSON string that represents the resource.
        }
        else
        {
            throw new Exception("Hash mismatch.");
            // Do not attempt to decrypt encryptedPayload. Assume notification payload has been tampered with and investigate.
        }


    }
}