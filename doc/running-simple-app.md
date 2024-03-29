Running Simple Applications
===================================

Introduction
------------
This guide explains how to run your application in Mystikos for simple development
and testing. For a guide on how to package your application for production usage,
refer to [doc/sign-package.md](/doc/sign-package.md). 

This guide assumes you already have an application directory (appdir) populated with
your application and any necessary dependencies. For help creating an application
directory, refer to the user-getting-started guides (for example, 
[doc/user-getting-started-c.md](/doc/user-getting-started-c.md)).

Mounting a file system
------------

To run applications in Mystikos, we need to mount the directory containing the
application and dependencies as a file system. There are three different
ways to mount a file system in Mystikos.

### Root file system (rootfs)

Every application will have a root file system. When a rootfs is passed to
`myst`, Mystikos will automatically mount it. This file system will contain
the entry point into your application. This guide will focus mainly on
mounting a rootfs.

> Unless you need to mount additional directories beyond your application
directory, you will only need a root file system.

### Configuration Mount

This mount is specified in configuration and handled by Mystikos. File system
changes do not require a new application image. Refer to
[doc/design/mount-config-design.md](/doc/design/mount-config-design.md)
for more details.

### Explicit Mount (`mount()` syscall)

Mounting within the application is also supported. Configuration mount is
recommended over explicit mount.

File System Types
------------

Before we can mount the application directory, we must first generate a file system image.
The file system image generated determines which file system type is used. There are currently
three file systems in Mystikos. 

### CPIO

Choose this for small applications. The entire file system will be loaded into memory when the
application runs. When packaging your application for production, your application directory
will be part of the executable image.

### Ext2

Choose this for larger applications; EXT2 uses less memory than CPIO. The file system image is a
separate file from the executable.

Mystikos supports the following features:
- Usage of ephemeral EXT2 file systems
- Integrity checking of EXT2 file systems ([dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html) compatible)
- Encryption of EXT2 file systems ([dm-crypt](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html) compatible)

Modifications to EXT2 file systems are discarded when the application terminates. 
Currently, writes are cached in trusted memory, so the number of block writes is limited by
available memory. This limitation may be overcome later with an encrypted backing store.

To support these features, Mystikos runs the following modules within the
trusted execution environment (TEE).

- EXT2 file system driver (ext2)
- Block integrity checking device (dm-verity)
- Block encryption device (dm-crypt)
- Block cache device

The EXT2 image itself resides on the untrusted file system. The TEE transitions
into the untrusted execution environment to fetch blocks. The blocks are then
decrypted and integrity-checked within the TEE.

EXT2 images generated by Mystikos has the following layout, divided into three
sections.

| EXT2 file system | hash device | file-system signature (fssig) |
| ---------------- |:-----------:| -----------------------------:|

The first section is a Linux-compatible EXT2 file system. The next section is
a Linux-compatible dm-verity hash device (Merkle tree). The final section is
a 4096-byte proprietary structure that defines the **root hash** of the
Merkle tree and an optional **digital signature** of the root hash.

### Host file system (insecure)

Mystikos supports mounting directories from the host file system. This option is not secured
by the enclave, but is useful for applications that need to manipulate untrusted data on the 
host.

> Mystikos applications may use a mixture of file system types and mount types.

Creating a Simple Application Image
----------------------

This section explains how to create single-file images for use with
Mystikos.

### CPIO

The following command creates a CPIO image (``cpioimage``) from the
contents of a directory (``appdir``).

```
$ myst mkcpio appdir cpioimage
```
### EXT2

The following command creates an EXT2 image (``ext2image``) from the
contents of a directory (``appdir``).

```
$ myst mkext2 appdir ext2image
```

> To create a signed EXT2 image to use with a signed application package, see [sign-package.md](./sign-package.md)

Loading a root file system
--------------------------------

This section explains how to use an application image as a Mystikos root file system
(or rootfs).

### Using an application image during development
During development, an application image is passed to the ``myst exec`` command as
follows.

```
$ myst exec-sgx <rootfs> /bin/hello
Hello World!
```

> `<rootfs>` can be a CPIO image, an EXT2 image, or a hostfs directory name.

Advanced Features
------------
## Creating an encrypted EXT2 image 

The following command creates an encrypted EXT2 image.

```
$ myst mkext2 --encrypt=keyfile ext2image
```

Use the following command generate a test keyfile.

```
$ head -c 64 /dev/urandom > keyfile
```

The EXT2 image created above can be decrypted by a Mystikos image that possesses
the key. Key distribution is left to the application. An encrypted image cannot
be used as the root file system.
