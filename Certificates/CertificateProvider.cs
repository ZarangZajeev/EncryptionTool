using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionTool.Certificates
{
    public class CertificateProvider
    {
        private readonly X509Certificate2 _certificate;

        public CertificateProvider()
        {
            var subjectName = "BM.WRK.CERT";

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            _certificate = store.Certificates
                .Find(X509FindType.FindBySubjectName, subjectName, false)
                .OfType<X509Certificate2>()
                .FirstOrDefault()
                ?? throw new Exception("Certificate not found");

            store.Close();
        }

        public X509Certificate2 GetCertificate() => _certificate;
    }
}
