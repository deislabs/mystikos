# Confidential Machine Learning and Multi-party Computing

This solution demonstrates how two parties, the data owner and the inference
model owner, could collaborate by sending their confidential information to a
trusted application running in a TEE, Mystikos in this case and perform
image classification using PyTorch and AlexNet. The confidentiality of the
data and the model are preserved throughout the process.

When the inference server starts, it obtains two symmetric keys, one
for the image data, one for the inference model, via
[Secure Secret Release](https://github.com/deislabs/mystikos/blob/main/doc/design/secret-provisioning.md).

The server downloads the encrypted inference model from the web, and decrypts
it with the obtained symmetric key for the model. While serving web requests,
it checks whether the image file in the request is encrypted. And if yes,
it uses the symmetric key for data to decrypt the image file, and send it
to the inference engine.

The results of the inference could be optionally encrypted.

## Prerequisites

1. The inference model owner must create a symmetric key and stored it on
[Azure Managed HSM](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/secure-your-managed-hsm)
along with a release policy for the key. Please contact MHSM team for the details.

1. Same applies to the image data owner.

1. The inference model file(s) must be encrypted with the key created in
step 1, and uploaded to a publicly accessible hosting site. An example command is like:
    ```bash
    openssl enc -e -p -aes256 -K <AES KEY> -in alexnet-pretrained.pt -out alexnet-pretrained.pt.encrypted -iv 0
    ```

1. The data owner must encrypt the image files with the key created in step 2.

For this solution, we have already done step 1-4.

## Environment

The following environment variables are required by MHSM and Secure Secret
Release. They must be set on the machine that we deploy the application to:
```bash
export CLIENT_ID=<your-client-id-for-azure-aad> 
export CLIENT_SECRET=<your-client-secret-for-azure-aad>
export APP_ID=<your-tenant-id-for-azure>
export MHSM_AAD_URL=<the-url-for-MHSM-aad>
export SSR_PKEY=<the-key-specified-in-the-release-policy>
```

For security reasons, these environment variables are kept confidential
from unauthorized users. We run this solution on CI/CD pipelines via
secret environment variables.

## Configurations

Users can configure where to retrieve the two symmetric keys with
`config.json`:

```
    "Secret": [
        {
            "ID": "PytorchModelKey",
            "SrsAddress": "https://accmhsm.managedhsm.azure.net",
            "SrsApiVersion": "7.3-preview",
            "LocalPath": "/model.key",
            "ClientLib": "libmhsm_ssr.so"
        },
        {
            "ID": "PytorchDataKey",
            "SrsAddress": "https://accmhsm.managedhsm.azure.net",
            "SrsApiVersion": "7.3-preview",
            "LocalPath": "/image.key",
            "ClientLib": "libmhsm_ssr.so"
        }
    ]
```

## Run the sample

To make and run this solution, use: 
```
make && make run 
```

The script launches both the inference server and the client. The client sends
3 unencrypted image files to the server for classification, followed by 3
encrypted files of the same images.

For demo purpose, the results of the inferences are shown on the screen
as plain text. We can easily augment the confidentiality, if the users
want it, by encrypting the results as well.

## Running in Azure Kubernetes Service (AKS)

Set the environment variables required in: 
1. confml_server.yaml
```bash
CLIENT_ID=<your-client-id-for-azure-aad> 
CLIENT_SECRET=<your-client-secret-for-azure-aad>
APP_ID=<your-tenant-id-for-azure>
MHSM_AAD_URL=<the-url-for-MHSM-aad>
```
2. confml_aks_demo.sh
```bash
RESOURCE_GROUP=
CLUSTER_NAME=
```
3. On the current machine (so you can run `make` and create the docker container, this only needs to be done once)
```bash
export CLIENT_ID=<your-client-id-for-azure-aad> 
export CLIENT_SECRET=<your-client-secret-for-azure-aad>
export APP_ID=<your-tenant-id-for-azure>
export MHSM_AAD_URL=<the-url-for-MHSM-aad>
export SSR_PKEY=<the-key-specified-in-the-release-policy>
```
4. Add the name of your docker container to the `Makefile` and the `confml_client.yaml` and `confml_server.yaml`

Once the environment varibles have been set, run: 
```
make && make demo
```
