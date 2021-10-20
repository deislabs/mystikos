using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace dotnet
{
    public class MAARequestBody
    {
        public class AttestedData
        {
            public string Data { get; set; }
            public string DataType { get; set; }
        }

        public static string EncodeBytes(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public MAARequestBody(byte[] report, byte[] runtimeData)
        {
            Report = EncodeBytes(report);
            RuntimeData = new AttestedData()
            {
                Data = EncodeBytes(runtimeData),
                DataType = "Binary",
            };
        }

        public string Report { get; set; }
        public AttestedData RuntimeData { get; set; }
        public AttestedData InittimeData { get; set; }
        public string DraftPolicyForAttestation { get; set; }
    }

    class Program
    {
        static async Task<string> testMAARequest(string maa_endpoint, MAARequestBody requestBody)
        {
            var uri = $"https://{maa_endpoint}:443/attest/OpenEnclave?api-version=2020-10-01";
            Console.WriteLine(uri);
            var request = new HttpRequestMessage(HttpMethod.Post, uri);
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody), null, "application/json");

            // Send request
            var theHttpClient = new HttpClient();
            var response = await theHttpClient.SendAsync(request);

            // Analyze failures
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new Exception($"AttestOpenEnclaveAsync: MAA service status code {(int)response.StatusCode}.  Details: '{body}'");
            }

            // Return result
            var jwt = await response.Content.ReadAsStringAsync();
            return jwt.Trim('"');
        }

        static async Task Main(string[] args)
        {
            Console.WriteLine("Hello C# World from Mystikos :-)");
            string certFile = "/tmp/myst.crt";
            string pkeyFile = "/tmp/myst.key";
            string reportFile = "/tmp/myst.report";

            // Load the certificate into an X509Certificate object.
            X509Certificate2 cert = new X509Certificate2(File.ReadAllBytes(certFile));
            Console.WriteLine("Subject: {0}", cert.Subject);

            // Warning: Don't use the following methods/attributes to retrieve the
            // public key from a Mystikos-generated x509 certificate:
            //
            // X509Certificate2.GetPublicKey() or
            // X509Certificate2.GetPublicKeyString() or
            // X509Certificate2.PublicKey or
            // X509Certificate2.PublicKey.Key
            //
            // The "public key" referred to by other tools/lanuages, including openssl
            // and Java, is oddly called "SubjectPublicKeyInfo" by C#. We have to
            // manually cast the C# "public key" to the correct type, e.g., RSA/ECDSA/etc.,
            // and call ExportSubjectPublicKeyInfo to reach the same key that
            // everybody else called the "public key".
            //
            // To be fair, C#'s terminology is more aligned with the x509 RFC
            // https://tools.ietf.org/html/rfc3279. But in the RFC, the "public key"
            // doesn't have descriptor thus makes it nonportable. That's why everybody
            // else called the enclosing structure which includes the descriptor and the
            // naked key the "public key".

            Console.WriteLine("Public key w/o descriptor: {0}", cert.GetPublicKeyString());

            byte[] public_key =((RSA)(cert.PublicKey.Key)).ExportSubjectPublicKeyInfo();
            Console.Write("Real public_key {0} bytes): ", public_key.Length);
            foreach(byte b in public_key)
            {
                Console.Write("{0:X2}", b);
            }
            Console.WriteLine();

            byte[] report = File.ReadAllBytes(reportFile);
            Console.Write("Report ({0} bytes): ", report.Length);
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

            var maa_endpoint = Environment.GetEnvironmentVariable("MAA_SHARED_URL");
            if (maa_endpoint != null)
            {
                // Build request and test with MAA
                var requestBody = new MAARequestBody(report, public_key);
                var serviceResponse = await testMAARequest(maa_endpoint, requestBody);
                var serviceJwtToken = JObject.Parse(serviceResponse)["token"].ToString();
                Console.WriteLine("MAA test passed. MAA token: {0}", serviceJwtToken);
            }
        }
    }
}
