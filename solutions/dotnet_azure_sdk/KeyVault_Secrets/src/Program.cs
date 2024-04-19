// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Identity;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Secrets.Samples
{
    /// <summary>
    /// This sample demonstrates how to create, get, update, and delete a secret in Azure Key Vault using asynchronous methods of <see cref="SecretClient"/>.
    /// </summary>
    public partial class HelloWorld
    {
        static async Task<int> Main()
        {
            // Environment variable with the Key Vault endpoint.
            string keyVaultUrl = Environment.GetEnvironmentVariable("AZURE_KEYVAULT_URL");

            // Notice that the client is using default Azure credentials. To make default credentials work, ensure that you 
            // have either a managed identity, or an app registration with environment variables 'AZURE_CLIENT_ID', 
            // 'AZURE_CLIENT_KEY' and 'AZURE_TENANT_ID' are set with the service principal credentials.
            // Alternatively, other authentication mechanisms can be used. For more information see
            // See https://learn.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme?view=azure-dotnet
            var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

            int repeat = 0;
            const int total = 3;
            while (++repeat <= total)
			{
                Console.WriteLine("Repeat #{0}...", repeat);
                try
                {
                    string secretName = $"BankAccountPassword-{Guid.NewGuid()}";

                    var secret = new KeyVaultSecret(secretName, "f4G34fMh8v");
                    secret.Properties.ExpiresOn = DateTimeOffset.Now.AddYears(1);

                    await client.SetSecretAsync(secret);

                    KeyVaultSecret bankSecret = await client.GetSecretAsync(secretName);
                    Console.WriteLine($"Secret is returned with name {bankSecret.Name} and value {bankSecret.Value}");

                    bankSecret.Properties.ExpiresOn = bankSecret.Properties.ExpiresOn.Value.AddYears(1);
                    SecretProperties updatedSecret = await client.UpdateSecretPropertiesAsync(bankSecret.Properties);
                    Console.WriteLine($"Secret's updated expiry time is {updatedSecret.ExpiresOn}");

                    var secretNewValue = new KeyVaultSecret(secretName, "bhjd4DDgsa");
                    secretNewValue.Properties.ExpiresOn = DateTimeOffset.Now.AddYears(1);

                    await client.SetSecretAsync(secretNewValue);

                    DeleteSecretOperation operation = await client.StartDeleteSecretAsync(secretName);

                    #region Snippet:SecretsSample1PurgeSecretAsync
                    // You only need to wait for completion if you want to purge or recover the secret.
                    await operation.WaitForCompletionAsync();

                    await client.PurgeDeletedSecretAsync(secretName);
                    #endregion
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
