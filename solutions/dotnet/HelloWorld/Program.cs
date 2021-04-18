using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace dotnet
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello C# World from Mystikos :-)");
            string certFile =  "/tmp/myst.crt";
            string reportFile = "/tmp/myst.report";

            // Load the certificate into an X509Certificate object.
            X509Certificate cert = X509Certificate.CreateFromCertFile(certFile);
            Console.WriteLine("Subject: {0}", cert.Subject);

            Console.Write("Public key: ");
            foreach(byte b in cert.GetPublicKey())
            {
                Console.Write("{0:X2}", b);
            }
            Console.WriteLine();

            byte[] report = File.ReadAllBytes(reportFile);
            Console.Write("Report: ");
            foreach(byte b in report)
            {
                Console.Write("{0:X2}", b);
            }
            Console.WriteLine();
        }
    }
}
