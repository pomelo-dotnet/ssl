using System;
using System.IO;
using Xunit;

namespace Pomelo.Security.Ssl.Tests
{
    public class UnitTest1
    {
        private readonly OpenSSL ssl;

        public UnitTest1()
        {
            if (Directory.Exists("ssldb"))
            {
                Directory.Delete("ssldb", true);
            }

            ssl = new OpenSSL("C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe");
        }

        [Fact]
        public void Test1()
        {
            // Generate Root CA
            ssl.GenerateRsaPrivateKey("ca.key", "123456");
            ssl.GenerateCsr("ca.csr", "ca.key", "123456");
            ssl.GenerateSelfSignedCert("ca.csr", "ca.key", "ca.crt", 7200, "123456");
            ssl.ConvertCrtAndKeyToPfx("ca.crt", "ca.key", "ca.pfx", "123456", "123456");

            // Generate intermediate CA
            ssl.GenerateRsaPrivateKey("sub.key", "123456");
            ssl.GenerateCsr("sub.csr", "sub.key", "123456", "CN", "Shanghai", "Shanghai", "Pomelo Foundation", "Open Source Department", "Pomelo Foundation Test CA");
            ssl.SignIntermediateCaCert("sub.csr", "sub.crt", 7200, "ca.crt", "ca.key", "123456", crlUrls: new[] { "http://crl.pomelo.cloud/pomelo.crl" });

            // Generate intermediate CA 2
            ssl.GenerateRsaPrivateKey("subsub.key", "123456");
            ssl.GenerateCsr("subsub.csr", "subsub.key", "123456", "CN", "Shanghai", "Shanghai", "Pomelo Foundation", "Open Source Department", "Pomelo Foundation Test Sub CA");
            ssl.SignIntermediateCaCert("subsub.csr", "subsub.crt", 7200, "sub.crt", "sub.key", "123456", crlUrls: new[] { "http://crl.pomelo.cloud/pomelo.crl" });

            // Generate user cert
            ssl.GenerateRsaPrivateKey("user.key", "123456");
            ssl.GenerateCsr("user.csr", "subsub.key", "123456", "CN", "Shanghai", "Shanghai", "Pomelo Foundation", "Open Source Department", "pomelo.cloud", "domain@pomelo.cloud");
            ssl.SignServerCert("user.csr", "user.crt", 366, "subsub.crt", "subsub.key", "123456", dns: new[] { "pomelo.cloud", "*.pomelo.cloud" } , crlUrls: new[] { "http://crl.pomelo.cloud/pomelo.crl" });
        }
    }
}
