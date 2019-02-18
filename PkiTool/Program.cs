using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CryptLink.SigningFramework;
using OpenSSL.PrivateKeyDecoder;
using OpenSSL.X509Certificate2Provider;
using PemUtils;

namespace PkiTool
{
    class Program
    {
        private static DateTime NotAfter = new DateTime(2050, 1, 1, 0, 0, 0);
        private static X509Certificate2 _ca, _server, _licroot;

        static X509Certificate2 ReadWithPrivKey(string name)
        {
            var pubCert = File.ReadAllText("output/" + name + ".crt");
            Console.WriteLine($"Please paste the private key for {name.ToUpper()} and press enter:");
            StringBuilder sb = new StringBuilder();
            for (; ; )
            {
                var line = Console.ReadLine();
                sb.AppendLine(line);
                if (line.Contains("-----END RSA PRIVATE KEY-----")) break;
            }
            while (Console.KeyAvailable) Console.ReadKey(false);
            Console.WriteLine("Private key read\n");
            return new CertificateFromFileProvider(pubCert, sb.ToString()).Certificate;
        }

        static string ReadWithDefault(string what, string fallback)
        {
            Console.Write($"{what} [{fallback}]>");
            var resp = Console.ReadLine();
            return string.IsNullOrWhiteSpace(resp) ? fallback : resp;
        }

        static void CreateCA()
        {
            var name = ReadWithDefault("CertName", "MobileCare CA");
            _ca = new CertBuilder { SubjectName = $"CN={name}", KeyStrength = 2048, NotAfter = NotAfter }.BuildX509();
            File.WriteAllText("output/ca.crt", _ca.ExportPemCertificate());
            Console.WriteLine("CA private key:");
            Console.WriteLine(_ca.ExportPemPrivateKey());
        }

        static void CreateServer()
        {
            _ca = _ca ?? ReadWithPrivKey("ca");
            var name = ReadWithDefault("CertName", "MobileCare Server localhost");
            var host = ReadWithDefault("Hostname", "localhost");
            _server = new CertBuilder { SubjectName = $"CN={name}", AltNames = new[] { host }, Issuer = _ca, KeyStrength = 2048, NotAfter = NotAfter }.BuildX509();
            var pw = ReadWithDefault("PFX Password, default = none", "");
            File.WriteAllBytes($"output/{host}.encrypted.pfx", _server.Export(X509ContentType.Pfx, pw));
            Console.WriteLine($"File {host}.encrypted.pfx written");
        }

        static void CreateLicenseRoot()
        {
            _ca = _ca ?? ReadWithPrivKey("ca");
            var name = ReadWithDefault("CertName", "MobileCare Licensing Root 0");
            _licroot = new CertBuilder { SubjectName = $"CN={name}", Issuer = _ca, KeyStrength = 2048, NotAfter = NotAfter }.BuildX509();
            File.WriteAllText("output/licroot.crt", _licroot.ExportPemCertificate());
            var pw = ReadWithDefault("PFX Password, default = none", "");
            File.WriteAllBytes($"output/licroot.pfx", _licroot.Export(X509ContentType.Pfx, pw));
            Console.WriteLine("Licensing root private key:");
            Console.WriteLine(_licroot.ExportPemPrivateKey());
        }

        static void CreateUserLicense()
        {
            _licroot = _licroot ?? ReadWithPrivKey("licroot");
            var ca = new X509Certificate2("output/ca.crt");
            var site = ReadWithDefault("Site", "kpvbregenz");
            var userName = ReadWithDefault("User", "PC101");
            var user = new CertBuilder { SubjectName = $"CN={userName},O={site}", Intermediate = false, Issuer = _licroot, KeyStrength = 2048, NotAfter = NotAfter }.BuildX509();
            var pubLicRoot = new X509Certificate2(_licroot) { PrivateKey = null };
            var combined = new X509Certificate2Collection(new[] { user, pubLicRoot, ca });
            File.WriteAllBytes($"output/license-{site}-{userName}.pfx", combined.Export(X509ContentType.Pfx));
            Console.WriteLine($"File license-{site}-{userName}.pfx written");
        }

        
        static void CreateUserLicense2()
        {
            _ca = _ca ?? ReadWithPrivKey("ca");
            var site = ReadWithDefault("Site", "kpvbregenz");
            var userName = ReadWithDefault("User", "PC101");
            var user = new CertBuilder { SubjectName = $"CN={userName},O={site}", Intermediate = false, Issuer = _ca, KeyStrength = 2048, NotAfter = NotAfter }.BuildX509();
            File.WriteAllBytes($"output/license-{site}-{userName}.pfx", user.Export(X509ContentType.Pfx));
            Console.WriteLine($"File license-{site}-{userName}.pfx written");
        }

        static void Main(string[] args)
        {
            try { Directory.CreateDirectory("output"); } catch { }

            for (; ; )
            {
                Console.WriteLine("\n[C] ReCreate CA\n" +
                                  "[S] ReCreate server cert\n" +
                                  "[R] ReCreate licensing root\n" +
                                  "[L] New user license\n" +
                                  "[X] New user license from CA");

                Console.Write("Command>");
                var inp = Console.ReadLine();
                var chr = string.IsNullOrWhiteSpace(inp) ? "_" : inp.Substring(0, 1).ToUpper();
                switch (chr)
                {
                    case "C":
                        CreateCA();
                        break;
                    case "S":
                        CreateServer();
                        break;
                    case "R":
                        CreateLicenseRoot();
                        break;
                    case "L":
                        CreateUserLicense();
                        break;
                    case "X":
                        CreateUserLicense2();
                        break;
                }
            }
        }
    }

    public static class CertExtensions
    {
        public static string ExportPemCertificate(this X509Certificate2 cert)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");
            return builder.ToString();
        }

        public static string ExportPemPrivateKey(this X509Certificate2 cert)
        {
            using (var stream = new MemoryStream())
            {
                using (var writer = new PemWriter(stream))
                    writer.WritePrivateKey(cert.GetRSAPrivateKey());

                stream.Seek(0, SeekOrigin.Begin);

                using (var reader = new StreamReader(stream, Encoding.ASCII))
                    return reader.ReadToEnd();
            }
        }
    }
}
