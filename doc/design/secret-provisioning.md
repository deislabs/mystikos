# Proposal: Flexible Secret provisioning with Mystikos

For confidential computing applications, we don't recommend that the
application code to contain any secrets, as the code (either in source
or binary forms) could be exposed to hostile environment during
downloading, uploading, copying, or launching of the application.
Instead, we recommend the secrets to be securely released to the
application while it is executed in a Trused Execution Environment (TEE).
The providers of the secrets could be a key vault service such as AKV,
M-HSM, or a service run by the user in a locked down and trusted
environment.

This design document describes the process of provisioning a pre-generated
secret into an application running with Mystikos in 4 components as below.
How the secret is generated is outside the scope of this document. We will
likely revise the design when gaps are found in a PoC.

1. **the user interface**
1. **the client library**
1. **the server library**
1. **the Secret Release Service (SRS)**

Users are responsible for:

1. Run their own Secret Release Service, or utilize an existing key vault service
such as Azure Managed HSM;
1. Develop/choose a pair of client lib and server lib that satisfies the security
requirements. We provide reference implementation of these libraries that can be
reused/customized for secret provisioning. We also provide a client library
for Azure Managed HSM service;
1. While creating self-contained appdir and rootfs for the application with
`myst-appbuilder`, ensure the client library (and whatever libraries it depends on)
are placed on a default library path, "/lib/" for example;
1. Link SRS service with the server lib (not required if using Azure Managed HSM);
1. Config Mystikos application (see "The user interface" section).

Mystikos is responsible for:

1. Perform secret provisioning during boot time if the `secrets` section is present
in config.json;
1. If secret provisioning is successful, write the secret to the file at `LocalPath`.
The application can access the secret by reading the file;
1. If secret provisioning failed, the Mystikos runtime still boots up and launches
the application, but reports a failure to the uer.

## The user interface

Users who wish to provision secrets to their applications running with
Mystikos should add the following section to config.json:

```json
secrets: [
    # Secret 1
    {
        "ID": <ID of the secret>,
        "SrsAddress": <Address to the Secret Release Service>,
        "SrsApiVersion": <Optional. API Version of the SRS>,
        "LocalPath": <Path of the file that stores the secret after its retrieval>,
        "ClientLib": <Name of the client library>,
        "Verbose": <Optional. Verboseness of the client library>
    },
    # Secret 2
    {
        "ID": <ID of the secret>,
        "SrsAddress": <Address to the Secret Release Service>,
        "SrsApiVersion": <Optional. API Version of the SRS>,
        "LocalPath": <Path of the file that stores the secret after its retrieval>,
        "ClientLib": <Name of the client library>,
        "Verbose": <Optional. Verboseness of the client library>
    },
    ...
]
```

## The client library

We will provide: 1) a reference implementation of the client library;
and 2) a client library for MHSM that exposes the following APIs:

```c

typedef struct _releasedSecret
{
    uint32_t schemaVersion; /* schema version of this structure */
    char* id;               /* ID of the secret */
    char* category;         /* key/cert/etc. */
    char* type;             /* RSA/EC/AES/etc. */
    char* description;      /* optional desc. from the secret service */
    uint8_t* data;          /* the secret as a binary blob */
    size_t length;          /* the length of the blob */
} ReleasedSecret;

/// Set the verbose level of the client library
int ssr_client_set_verbose(unsigned level);

/// Initialize the client library
int ssr_client_init(void);

/// Retrieve a secret from the SRS service, given the
/// secret ID, the service address, the API version
/// of the service.
///
/// If successful, the function returns 0 and the secret
/// is written into the structure **secret**. Returns
/// an error code otherwise.
int ssr_client_get_secret(
    const char* srs_addr,
    const char* api_version,
    const char* id,
    ReleasedSecret* secret);

/// Free the contents of the release secret, but not the
/// **secret** pointer itself.
void ssr_client_free_secret(ReleasedSecret* secret);

/// Tear down the client library.
void ssr_client_terminate(void);
```

Users can plug in their own client library, provided the library implements
the above API surface, by including the library in a default library path
of rootfs and specifying the corresponding `ClientLibrary` in config.json.

The client library is expected to be written in C/C++.

## The server library

We will provide a reference implementation of the server library
that exposes the following APIs to be called by the reference
implementation of the SRS service:

```c

/// Set the verbose level of the server library
int ssr_server_set_verbose(unsigned level);

/// Initialize the server library
int ssr_server_init(void);

/// Validate credentials from the client. If valid,
/// wrap the secret with a key agreed on by both the client
/// lib and the server lib. The wrapped secret is written
/// into the **wrapped_secret_blob**, with its length
/// written into **wrapped_secret_blob_size**.
int ssr_server_validate_and_release_secret(
    const uint8_t* credential,
    size_t credential_size,
    uint64_t nonce,
    uint8_t **wrapped_secret_blob,
    size_t * wrapped_secret_blob_size);

/// Tear down the server library.
void ssr_server_terminate(void);
```

How does the server lib verify the credential and wrap the secret is a
contract between the client lib and the server lib.

## The Secret Release Service

The Secret Release Service (SRS) could be run in a trusted environment.
We recommend, but don't mandate, it to be run in a TEE. That is, we encourage
users to run SRS with Mystikos. But you could run it on a plain Linux or Windows
server as long as you have confidence in the measures that safeguard the server.

For testing purpose, we will provide a simple web service that links with
the reference implementation of the server library and performs secret release.

The Secret Release Service can be implemented in any programming language.

## Putting everything together

![](./secret-provision.png)
