using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace dotnet
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello C# World from Mystikos :-)");
            string certFile = "/tmp/myst.crt";
            string pkeyFile = "/tmp/myst.key";
            string reportFile = "/tmp/myst.report";

            // Load the certificate into an X509Certificate object.
            X509Certificate2 cert = new X509Certificate2(File.ReadAllBytes(certFile));
            Console.WriteLine("Subject: {0}", cert.Subject);

            Console.WriteLine("Public key: {0}", cert.GetPublicKeyString());

            byte[] report = File.ReadAllBytes(reportFile);
            Console.Write("Report ({0} bytes): ", report.Length);
            foreach(byte b in report)
            {
                Console.Write("{0:X2}", b);
            }
            Console.WriteLine();

            string pem = System.IO.File.ReadAllText(pkeyFile);
            const string header = "-----BEGIN RSA PRIVATE KEY-----";
            const string footer = "-----END RSA PRIVATE KEY-----";

            if (pem.StartsWith(header))
            {
                // The private key file is in PEM format. Read and parse the DER structure.
                int endIdx = pem.IndexOf(footer, header.Length, StringComparison.Ordinal);
                string base64 = pem.Substring(header.Length, endIdx - header.Length);
                byte[] der = Convert.FromBase64String(base64);

                // Import the private key into the cert.
                RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(der, out _);
                cert = cert.CopyWithPrivateKey(rsa);
                Console.WriteLine("Imported RSA private key into cert");

                // Export the RSA parameters of both private key and public key,
                // and make sure they match.
                var privateParams = rsa.ExportParameters(false);
                var rsaPublic = RSA.Create();
                rsaPublic.ImportRSAPublicKey(cert.GetPublicKey(), out _);
                var publicParams =  rsaPublic.ExportParameters(false);
                Debug.Assert(privateParams.Exponent.SequenceEqual(publicParams.Exponent));
                Debug.Assert(privateParams.Modulus.SequenceEqual(publicParams.Modulus));
                Console.WriteLine("Verified private key and public key match. Key size: {0}", publicParams.Modulus.Length*8);
            }
        }
    }
}
