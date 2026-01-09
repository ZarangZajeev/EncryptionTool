using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionTool.Certificates
{
    public class CryptoService
    {
        private readonly X509Certificate2 _certificate;

        public CryptoService(CertificateProvider provider)
        {
            _certificate = provider.GetCertificate();
        }

        private string ProtectedDevKey()
        {
            return "@!%Bum48893!*(";
        }

        // Encrypt (Public Key + Dev Key)
        public string Encrypt(string plainText, string key)
        {
            //var combined = $"{ProtectedDevKey()}::{plainText}";
            var combined = $"{key}::{plainText}";
            var bytes = Encoding.UTF8.GetBytes(combined);

            var rsa = _certificate.GetRSAPublicKey();
            var encryptedBytes = rsa.Encrypt(
                bytes,
                RSAEncryptionPadding.OaepSHA256
            );

            return Convert.ToBase64String(encryptedBytes);
        }

        // Decrypt (Private Key + Dev Key validation)
        public string Decrypt(string cipherText, string key)
        {
            var bytes = Convert.FromBase64String(cipherText);

            var rsa = _certificate.GetRSAPrivateKey();
            var decryptedBytes = rsa.Decrypt(
                bytes,
                RSAEncryptionPadding.OaepSHA256
            );

            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);

            //var prefix = $"{ProtectedDevKey()}::";
            var prefix = $"{key}::";

            if (!decryptedText.StartsWith(prefix))
                throw new CryptographicException("Invalid developer key");

            return decryptedText.Substring(prefix.Length);
        }
    }
}
