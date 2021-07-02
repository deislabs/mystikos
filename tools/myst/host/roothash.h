// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _HOST_MYSTROOTHASH_H
#define _HOST_MYSTROOTHASH_H

#include <limits.h>

#include <myst/args.h>
#include <myst/buf.h>
#include <myst/sha256.h>

/* get --roothash options from command line arguments */
void get_roothash_options(int* argc, const char* argv[], myst_buf_t* buf);

/* extract roothashes from ext2 images (rootfs or the --mount options) */
int extract_roothashes_from_ext2_images(
    const char* rootfs,
    const myst_args_t* mount_mappings,
    myst_buf_t* buf);

/* generate a filename and write SHA-256 hashes to that file */
int create_roothashes_file(myst_buf_t* buf, char filename[PATH_MAX]);

#endif /* _HOST_MYSTROOTHASH_H */
