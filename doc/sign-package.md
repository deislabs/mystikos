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

You can package your application directory `appdir` using the Mystikos tools (for instance, `myst package-sgx` for SGX target) to produce a single executable that will run your program within the target environment, be it an SGX enclave or the unprotected operating system.

For preparing to run under the SGX enclave you will need a couple of different things along with your existing `appdir`.

---

### Signing certificate for SGX enclave packaging

When an executable is run within an SGX enclave it is usually signed with a signing certificate that is controlled by the application developer. This signing certificate needs to be kept very secure as this helps to form part of the identity of the SGX enclave and can be used as part of the attestation for the application to prove it is running in an SGX enclave and the application is trustworthy using this key.

One way to get a key is to use OpenSSL with a command like this:

```bash
openssl genrsa -out private.pem -3 3072
```

> This key format is required by OpenEnclave, you can check more [here](https://github.com/openenclave/openenclave/blob/1d654764811c280980eb712aed5241176b3963a5/docs/GettingStartedDocs/buildandsign.md#signing-an-sgx-enclave)

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
    "ProductID": 1,
    "SecurityVersion": 1,

    "MemorySize": "40m",
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
    "HostEnvironmentVariables": ["TESTNAME"],
    "UnhandledSyscallEnosys": false
}
```

---

First we have the global settings for Mystikos.

Setting | Type | Description
-|-|-
version | `string` | Mystikos configuration version number. If the schema version is changed within Mystikos this version ties this configuration to a specific schema version. Current version is `"0.1"`

---

Next we have settings specific to configuring the SGX enclave itself.

Setting | Type | Description
-|-|-
Debug | `boolean \| int` | Enable debugging within the SGX enclave, turn off for release builds
ProductID | `int` | The product ID of your application.
SecurityVersion | `int` | Security version of your application.

---

Finally we have the Mystikos application specific settings.

Settings | Type | Description
-|-|-
~~UserMemSize~~ | `int \| string` | Deprecated, use `MemorySize` instead
MemorySize | `int \| string` | Amount of memory your application needs to run. Try not to make this just a very large number as the larger this number needs to be the slower load time will be. Value can be bytes (just a number), **k**ilobytes (for example `"128k"`), **m**egabytes (for example `"512m"`), or **g**igabytes (for example `"1g"`)
MainStackSize | `int \| string` | Stack size of your application's main process. Defaults to 1536k (or 1.5M) bytes. Normally, you do not need to customize this. If running an application generates a OOM error like in [#612](https://github.com/deislabs/mystikos/issues/612), try tuning this value, e.g. to 8M. Value can be bytes (just a number), **k**ilobytes (for example `"128k"`), **m**egabytes (for example `"512m"`), or **g**igabytes (for example `"1g"`)
ThreadStackSize | `int \| string` | The default stack size of pthreads created by the application. Ignored if smaller than the existing default thread stack size
MaxAffinityCPUs | `int` | This setting limits the number of CPUs reported by sched_getaffinity()
NoBrk | `boolean \| int` | If set to true(or 1), brk syscall returns -ENOTSUP. Defaults to `false`. Set this to true for program involves multi-threading.
ApplicationPath | `string` | The executable path relative to the root of your appdir. This executable name is also used to determine the final application name once packaged.
HostApplicationParameters | `boolean \| int` | This parameter specifies if application parameters can be specified on the command line or not. If true, the command line arguments are used instead of the ApplicationParameters
ApplicationParameters | `[string] \| string` | Enclave defined application parameters, effective if HostApplicationParameters is set to false.
EnvironmentVariables | `[string] \| string` | Enclave defined environment variables, an entry should be a key value pair like `"KEY=VALUE"`
HostEnvironmentVariables | `[string] \| string` | A string denoting a single variable , or a list of environment variables that can be imported from the untrusted host
CurrentWorkingDirectory | `string` | The default working directory for the application
Hostname | `string` | The default hostname exposed to application
ForkMode | `string` | Specify the mode used for the experimental pseudo fork feature. Refer to [doc/design/fork.md](/doc/design/fork.md) for more details. The default value is `"none"`, which disables the feature.
Mount | `object` | Set if parameters for informing Mystikos to automatically mount a set of directories or ext2 disk images from the host into the TEE. Refer to [doc/design/mount-config-design.md](/doc/design/mount-config-design.md) for more details. By default no extra mounts are added to the root filesystem.
UnhandledSyscallEnosys | `boolean \| int` | This option would prevent the termination of a program using myst_panic when the application invokes a syscall that is not handled by the Mystikos kernel. The default value is `false`, which implies that we terminate on unhandled syscalls by default. If `true`, it will cause the syscall to return an ENOSYS error.

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

In this example the appdir directory is converted to a CPIO archive before packaged into the single executable. This works for small directories, but if a lot of files reside in the appdir an ext2 may be better for performance reasons. Refer to [doc/using-ext2.md](/doc/using-ext2.md) for more details.

The result of this command is a single executable with the same application name as specified in the application path within the configuration.

> This executable can be renamed to anything other than `myst`

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

You then can ship your application in the form of this single exectuable to your desired platform.
