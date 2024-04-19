// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Identity;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Certificates.Samples
{
    /// <summary>
    /// This sample demonstrates how to create, get, update, and delete a certificate using the synchronous methods of the <see cref="CertificateClient">.
    /// </summary>
    public partial class HelloWorld
    {
        static async Task<int> Main()
        {
            // Environment variable with the Key Vault endpoint.
            string keyVaultUrl = Environment.GetEnvironmentVariable("AZURE_KEYVAULT_URL");

            // Instantiate a certificate client that will be used to call the service. Notice that the client is using
            // ManagedIdentityCrendetials. To make default credentials work, ensure that you have either a managed identity, or
            // an app registration with environment variables 'AZURE_CLIENT_ID', 'AZURE_CLIENT_KEY' and 'AZURE_TENANT_ID' are
            // set with the service principal credentials.
            // Other authentication mechanisms can be used. For more information see
            // See https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme?view=azure-dotnet
            CertificateClient client = new CertificateClient(new Uri(keyVaultUrl), new ManagedIdentityCredential());

            int repeat = 0; 
            const int total = 3;
            while (++repeat <= total)
            {
                Console.WriteLine("Repeat #{0}...", repeat);
                try
                {
                    // Let's create a self-signed certificate using the default policy. If the certificate
                    // already exists in the Key Vault, then a new version of the key is created.
                    string certName = $"defaultCert-{Guid.NewGuid()}";

                    CertificateOperation certOp = await client.StartCreateCertificateAsync(certName, CertificatePolicy.Default);

                    // Next, let's wait on the certificate operation to complete. Note that certificate creation can last an indeterministic
                    // amount of time, so applications should only wait on the operation to complete in the case the issuance time is well
                    // known and within the scope of the application lifetime. In this case we are creating a self-signed certificate which
                    // should be issued in a relatively short amount of time.
                    Response<KeyVaultCertificateWithPolicy> certificateResponse = await certOp.WaitForCompletionAsync();
                    KeyVaultCertificateWithPolicy createCertificate = certificateResponse.Value;

                    // At some time later we could get the created certificate along with its policy from the Key Vault.
                    KeyVaultCertificateWithPolicy getCertificate = await client.GetCertificateAsync(certName);

                    Console.WriteLine($"Certificate was returned with name {getCertificate.Name} which expires {getCertificate.Properties.ExpiresOn}");

                    // We find that the certificate has been compromised and we want to disable it so applications will no longer be able
                    // to access the compromised version of the certificate.
                    CertificateProperties certificateProperties = getCertificate.Properties;
                    certificateProperties.Enabled = false;

                    Response<KeyVaultCertificate> updatedCertResponse = await client.UpdateCertificatePropertiesAsync(certificateProperties);

                    Console.WriteLine($"Certificate enabled set to '{updatedCertResponse.Value.Properties.Enabled}'");

                    // We need to create a new version of the certificate that applications can use to replace the compromised certificate.
                    // Creating a certificate with the same name and policy as the compromised certificate will create another version of the
                    // certificate with similar properties to the original certificate
                    CertificateOperation newCertOp = await client.StartCreateCertificateAsync(getCertificate.Name, getCertificate.Policy);

                    KeyVaultCertificateWithPolicy newCert = await newCertOp.WaitForCompletionAsync();

                    // The certificate is no longer needed, need to delete it from the Key Vault.
                    DeleteCertificateOperation operation = await client.StartDeleteCertificateAsync(certName);

                    // You only need to wait for completion if you want to purge or recover the certificate.
                    await operation.WaitForCompletionAsync();

                    // If the keyvault is soft-delete enabled, then for permanent deletion, the deleted key needs to be purged.
                    await client.PurgeDeletedCertificateAsync(certName);
                }
                catch (RequestFailedException ex)
                {
                    Console.WriteLine($"Request failed! {ex.Message} {ex.StackTrace}");
                    return -1;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Unexpected exception! {ex.Message} {ex.StackTrace}");
                    return -1;
                }
            }
            Console.WriteLine("Success!");
            return 0;
        }
    }
}
