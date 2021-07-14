Using EXT2 file systems in Mystikos
===================================

Introduction
------------

This document explains how to use EXT2 file systems in Mystikos, which
supports the following Linux-compatible EXT2-related features.

- Usage of ephemeral EXT2 file systems
- Integrity checking of EXT2 file systems ([dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html) compatible)
- Encryption of EXT2 file systems ([dm-crypt](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html) compatible)

Mystikos supports emphemeral EXT2 file systems. Modifications to EXT2 file
systems are discarded when the application terminates. Currently, writes are
cached in trusted memory, so the number of block writes is limited by
available memory. This limitation may be overcome later with an encrypted
backing store.

To support these features, Mystikos runs the following modules within the
trusted execution environment (TEE).

- EXT2 file system driver (ext2)
- Block integrity checking device
- Block encryption device
- Block cache device

The EXT2 image itself resides on the untrusted file system. The TEE transitions
into the untrusted execution environment to fetch blocks. The blocks are then
decrypted and integrity-checked within the TEE.

Creating an EXT2 image
----------------------

This section explains how to create EXT2 single-file images for use with
Mystikos.

#### Creating a simple EXT2 image

The following command creates an EXT2 image (``ext2image``) from the
contents of a directory (``appdir``).

```
$ myst mkext2 appdir ext2image
```

The resulting image has the following layout, divided into three sections.

| EXT2 file system | hash device | file-system signature (fssig) |
| ---------------- |:-----------:| -----------------------------:|

The first section is a Linux-compatible EXT2 file system. The next section is
a Linux-compatible dm-verity hash device (Merkle tree). The final section is
a 4096-byte proprietary structure that defines the **root hash** of the
Merkle tree and an optional **digital signature** of the root hash.

The contents of the **fssig** may be displayed as follows.

```
$ myst fssig ext2image
magic=f55198a153624d38
version=1
hash_offset=8388608
root_hash=b2b382a8836d8ec5332a0c3f272981f75c111d52af3c93b84a649da3abaab8bf
signer=null
signature=null
signature_size=0
```
The root hash alone can be displayed with the ``--roothash`` option.

```
$ myst fssig --roothash ext2image
b2b382a8836d8ec5332a0c3f272981f75c111d52af3c93b84a649da3abaab8bf
```

The EXT2 image created above can be loaded by a Mystikos image that trusts the
given root hash (we will see later how this is configured).

#### Creating a signed EXT2 image

The following command creates a signed EXT2 image.

```
$ myst mkext2 --sign=public.pem:private.pem appdir ext2image
```

The ``public.pem`` and ``private.pem`` files are public and private keys
respectively. The following generates test keys with these names.

```
$ openssl genrsa -out private.pem -3 3072
$ openssl rsa -in private.pem -pubout -out public.pem
```

The EXT2 image created above can be loaded by a Mystikos application that
trusts the given signing authority (we will see later how this is configured).

#### Creating an encrypted EXT2 image

The following command creates an encrypted EXT2 image.

```
$ myst mkext2 --encrypt=keyfile ext2image
```

Use the following command generate a test keyfile.

```
$ head -c 64 /dev/random > keyfile
```

The EXT2 image created above can be decrypted by a Mystikos image that possesses
the key. Key distribution is left to the application.

Using EXT2 as a root file system
--------------------------------

This section explains how to use an EXT2 image as a Mystikos root file system
(or rootfs).

#### Using an EXT2 rootfs during development

During development, an EXT2 image is passed to the ``myst exec`` command as
follows.

```
$ myst exec-sgx ext2image /bin/hello
Hello World!
```

The file-system mounter fetches the root hash from the **fssig** section at
the end of the EXT2 image.

#### Packaging an EXT2 rootfs for production (with a trusted root hash)

The following command packages an EXT2 rootfs for production.

```
$ myst package --roothash=roothash private.pem config.json
```

The procedure is similar to packaging a directory or a CPIO archive, except
that the ``--roothash`` option is used to add a root hash to the signed
application (where the option argument is a file containing the root
hash in ASCII format). This option may be repeated. The signed applicaiton
maintains a list of **trusted root hashes** and only allows EXT2 images with
those root hashes to be mounted.

#### Packaging an EXT2 rootfs for production (with a trusted public key)

Digitally signed EXT2 images may be packaged with the following command,
where public.pem is the public key of the signing authority.

```
$ myst package --pubkey=public.pem private.pem config.json
```

The ``--pubkey`` option adds a public key to the signed application. This
option may be repeated. The signed application maintains a list of **trusted
public keys** and only allows EXT2 images signed by those signers to be mounted.

The advantage to trusted public keys (over trusted root hashes) is that the
signed application trusts any EXT2 image that has is signed by a given
certificate (which means the application does not have to be resigned).

Running a signed package with an EXT2 image
-------------------------------------------

Since the EXT2 image is separate from the signed application, its location must
be specified either by an environment variable (``MYST_ROOTFS``) or by an option
(``--rootfs``). For example,

```
$ MYST_ROOTFS=ext2image ./myst/bin/hello
```

Or equivalently,

```
$ ./myst/bin/hello --rootfs=ext2image
```

The signed application attempts to establish trust by (1) a root hash (from its
trusted root hash list) or (2) by a public key (from its trusted public key
list). If the application was signed in debug mode, the EXT2 image is loaded
unconditionally.

Mounting EXT2 images from applications
--------------------------------------

Applications may mount EXT2 file systems with the Linux ``mount()`` function as
delcared here.

```
    int mount(
        const char* source,
        const char* target,
        const char* filesystemtype,
        unsigned long mountflags,
        const void* data);
```

The ``source`` is the path of a directory on the trusted root file system where
the EXT2 file system will be mounted. The ``target`` is the path of the EXT2
image on the untrusted file system. The ``filesystemtype`` must be "ext2".
Consider the following example:

```
    mount(source, "/mnt/mydisk", "ext2", 0, NULL);
```

This mounts ``source`` onto the "/mnt/mydisk" directory. As before,
``source`` must refer to an EXT2 image that was generated with by the
``myst mkext2`` command (it must contain the hash tree and file-system
signature structure).

The application should be run (``myst exec-sgx``) or packaged
(``myst packaget-sgx``) with the ``--roothash`` or ``--pubkey`` option as
explained above (otherwise moutning will fail verification).

To mount an encrypted EXT2 image, the application passes the key to the
``mount()`` function as shown below.

```
    const char* args[] =
    {
        "key",
        key,
        NULL,
    };

    mount(source, "/mnt/mydisk", "ext2", 0, &args);
```

Securely obtaining the key form a trusted source is left to the application.
