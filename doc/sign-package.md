# Signing and packaging an application with Mystikos

During development of a confidential application, with few exceptions,
we can run/test the application without signing or packaging. However,
for production usage of the application, or if the application needs to
be configured in certain ways, we recommend signing or packaging the
application.

Signing takes the application folder, a config file, and a private key
only known to the owner of the application, and generates a signed
application that is ready for production.

Packaging takes this further, besides generated the signed application,
it also packages the myst kernel, the C-runtime, the application,
the config file, and other necessary bits into a single ELF image.
This results in a single file that can be easily deployed.

This document describes how to sign or package your application after you
have built the `appdir` folder. See other user getting started guides on
how to generate `appdir`.


## Packaging your application in Mystikos

In order to prepare your application to run under Mystikos you need to package your application directory `appdir` using the Mystikos tools to produce a single executable that will run your executable within the target environment, be it an SGX enclave or the none protected operating system.

For preparing to run under the SGX enclave you will need a couple of different things along with your existing `appdir`.

---

### Signing certificate for SGX enclave packaging

When an executable is run within an SGX enclave it is usually signed with a signing certificate that is controlled by the application developer. This signing certificate needs to be kept very secure as this helps to form part of the identity of the SGX enclave and can be used as part of the attestation for the application to prove it is running in an SGX enclave and the application is trustworthy using this key.

One way to get a key is to use OpenSSL with a command like this:

```bash
openssl genrsa -out private.pem -3 3072
```

For a production environment a self signed key is not sufficient and will need a trusted signing authority that can be validated.

This signing certificate will then be used later in the preparation of your application package.

---

### Application configuration for SGX enclave packaging

A Mystikos package needs configuration to control certain run-time environmental settings as well as settings that control how the application reads environmental data from the insecure host environment.

Included is a sample JSON configuration where the elements will be described next, and will be the `config.json` file that is used in the packaging.

```json
{
    "version": "0.1",

    "Debug": 1,
    "KernelMemSize": "4m",
    "StackMemSize": "256k",
    "NumUserThreads": 2,
    "ProductID": 1,
    "SecurityVersion": 1,

    "UserMemSize": "40m",
    "ApplicationPath": "/bin/hello",
    "ApplicationParameters": [
        "Enclave-red", "Enclave-blue",
        "Enclave-green", "Enclave-yellow",
        "Enclave-pink"
    ],
    "HostApplicationParameters": true,
    "EnvironmentVariables": [
        "ENC-ENVP-1=Enclave_envp_1",
        "ENC-ENVP-2=Enclave_envp_1"
    ],
    "HostEnvironmentVariables": ["TESTNAME"]
}
```

---

First we have the global settings for Mystikos.

---

Setting | Description
-|-
version | Mystikos configuration version number. If the schema version is changed within Mystikos this version ties this configuration to a specific schema version

---

Next we have settings specific to configuring the SGX enclave itself.

---

Setting | Description
-|-
Debug | Enable debugging within the SGX enclave, turn off for release builds
KernelMemSize | The amount of memory for the Mystikos kernel, in this case 4 MB
StackMemSize | Stack size for kernel
NumUserThreads | Number of threads allowed within the enclave. If more threads are created than this number thread creation will fail
ProductID | The product ID of your application. This is an integer value
SecurityVersion | Security version of your application. This is an integer value.

---

Finally we have the Mystikos application specific settings.

---

Settings | Description
-|-
UserMemSize | Amount of user memory your application needs to run. Try not to make this just a very large number as the larger this number needs to be the slower load time will be. In this case 40 MB. Value can be bytes (just a number), Kilobytes (number with k after), or megabytes (number with m after)
ApplicationPath | The executable path relative to the root of your appdir. This executable name is used to determine the final application name once packaged.
ApplicationParameters | Enclave defined application parameters if HostApplicationParameters is set to false.
HostApplicationParameters | This parameter specifies if application parameters can be specified on the command line or not. If true, the command line arguments are used instead of the ApplicationParameters list of parameters
EnvironmentVariables | Enclave defined environment variables
HostEnvironmentVariables | A list of environment variables that can be imported from the insecure host

---

### Packaging your application for SGX enclave packaging

Packaging of the executable requires all the things that have now been created:

* executable and supporting files in `appdir`
* signing certificate
* configuration

With these three things a package can be created with the following command:

```bash
myst package-sgx ./appdir private.pem config.json
```

During the packaging process all the Mystikos executables and shared libraries are pulled together with the application directory and configuration and signed with the signing certificate. All enclave resident pieces of Mystikos and the `appdir` are all measured during the signing process and this measurement is verified while the SGX enclave is created. If there is a mismatch then the loading will fail.

The result of this command is a single executable with the same name as specified in the configuration.

Execution is as simple as running the executable:

```bash
./myapp
```

If your configuration allows command line parameters from the insecure host then they can also be added to this command as well:

```bash
./myapp arg1 arg2
```

If the host arguments are not allowed to be passed then any specified within the configuration will be added when Mystikos transitions to the secure enclave.

If any host environment variables are configured as available within the SGX enclave, then this command will pass them though. Enclave specific environment variables will be added once Mystikos transfers control to the enclave.

---
