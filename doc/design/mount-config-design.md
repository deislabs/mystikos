# Automatic filesystem mount configuration design

During startup we need the ability to mount directories from the untrusted host into the enclave.
Currently an application can do this through a system call,
but this needs to be automated at start-up if the necessary configuration is given.
Configuration needed for a mount includes the mount source path which is on an untrusted filesystem,
mount target directory within the TEE filesystem,
and other data relating configuration like if it is read-only or not.

## Overview

Currently three file-systems are supported by Mystikos:

* ramfs is a CPIO archive that is totally TEE memory resident once loaded.
It is used for rootfs file-systems and is included as part of the tee integrity measurement.
A ramfs archive can also be included in the rootfs image and an application can mount that on a target mount point.
No encryption is supported.

* ext2fs filesystem image that is hosted in the non-TEE filesystem for a rootfs.
It is currently used for the rootfs filesystem and can be integrity protected and encrypted.
It can also be mounted from the rootfs directory to a target mount point by the application.
The integrity and encryption keys are part of the TEE measurement.

* hostfs is a directory residing within the insecure host that is mounted into the TEE.
More hostfs directories can be mounted to a target directory by the application.
There is no integrity checks done on this type of filesystem.

The first dilemma with mounts is the source of the mount is untrusted for ext2 and hostfs.
Only ext2 filesystem images support integrity and encryption where the integrity can be validated within the TEE.
If the decryption key can be achieved securely within the TEE then the decryption can be done securely too without the key being passed in from the host.

The second dilemma is that every host this runs on *can* have different disk layouts and the source of the mount may change every time.
This is especially true in a container world where different filesystem images may be downloaded to different temporary locations that may differ with each run.

When mounting file-systems into the TEE it is good to have the configuration that is secure being part of the measured configuration of the application,
but keep the host specific mount information separate and specifiable from separate configuration that is passed on the command-line.

## TEE configuration

A new node will be added to the JSON configuration that is used in the signing of the application through sign-sgx or package-sgx commands:

```json
mount: [
    {
        "Target": "<target>",
        "Type": "<type>",
        "Flags": [ "<flag>" ],
        "PublicKey": "<publicKey>",
        "Roothash": "<roothash>"
    },
    {
        "Target": "<target>",
        "Type": "<type>",
        "Flags": [ "<flag>", "<flag>" ]
    }
]
```

| Name | Value |
| -- | -- |
| Target | This is the target mount point within the TEE. This mount point path needs to already exist in the TEE filesystem. |
| Type | "ext2", "hostfs", "ramfs" |
| Flags | Optional field that specified flags like "ro", "rw". At this time no flags are supported. |
| PublicKey | For ext2 filesystems this is the public key used to validate the signing key of the ext2 filesystem when it is mounted. This configuration is not currently supported. |
| Roothash | For ext2 filesystems this is the root hash to validate integrity of an integrity protected ext2 filesystem when it is mounted. This configuration is not currently supported. |
| | |

TODO: The source of private key for accessing an encrypted filesystem is not handled in this document at this time.

There is no source location information in this configuration as this may change from one machine to the other.
The source location will be passed via a command line argument to the insecure host application described in the next location.

## Host configuration

On the non-TEE host we need to specify the source mount point and associate it with the TEE target mount point.
This needs to be more dynamic because each machine this is run on may have a different configuration.
It is even possible that the source location may change with every run if the source location is generated with each run.

The following new command line argument will be added:

```text
--mount <source>=<target>
```

| Name | Value |
| -- | -- |
| source | This is the source location of the mount, it has to be an absolute path. 1) For mounting hostfs, this path should point to a directory on untrusted host. 2) For mounting ext2, this path should point to a EXT2 archive on untrusted host. 3) For mounting ramfs, this path should point to a CPIO archive within TEE filesystem(rootfs).  |
| target | This is the mount point within the TEE. There needs to be an associated target mount configuration specified at signing for this location otherwise the mount will fail. This mount point path needs to already exist in the TEE filesystem. |

The target location is part of the TEE measurement which specifies that the target directory is being accessed from an insecure source.
This command line argument provides the mapping between the two.

## Current mount capabilities

An application run in Mystikos can call the SYS_mount syscall via the mount() CRT API to mount either an ext2, hostfs, or ramfs filesystems.
The API specifies the source path, target path, filesystem type, mount flags and a data parameter.
All three filesystems do not support mount flags.
Only ext2 supports the data parameter which it extracts the key from.

Other than the specification of the rootfs during launch there is no automatic way of creating a mount point inside the TEE without a the application itself calling the APIs.

## Design

During the signing of the application through sign-sgx or package-sgx commands via the myst command line tool the TEE mount configuration from the json configuration file is added to the signed application image and cannot be changed.

On a host machine or container the application will be run either as an application in a directory with signed binaries, or via the self contained package binary.
The new mount commandline parameter will be added to whatever command was used before, with one mount parameter option per mount point.

The myst command will then launch the Mystikos runtime into the TEE and will pass the mount command line parameters in.

Once the Mystikos kernel is entered the kernel will use the TEE-side JSON configuration and the command line parameters to call a set of myst_syscall_mount() calls, one for each mount point that is specified on the command line whos target path matches that of the mount JSON configuration.

At this point the existing mount behavior will work as it does today whereby an application accessing a file on the target mount point, and the kernel will access the specified source location.
The source location is calculated by removing the target mount point  path from the start of the filename and prepending the source mount point path to that.
The source and target paths will be normalized to produce fully specified path at the time the mounting happens, and the application filepath is also normalized to a fill path.
