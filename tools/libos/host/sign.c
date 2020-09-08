// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <libos/elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <errno.h>
#include <libos/strings.h>
#include <libos/file.h>
#include "parse_options.h"
#include "utils.h"
#include "libos_u.h"
#include "regions.h"

// Pulled in from liboesign.a
// Actual OE signer code from oesign tool.
int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* digest_signature,
    const char* x509,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id);

#define USAGE_SIGN "\
\n\
Usage: %s sign <thing-to-sign> [options] ...\n\
\n\
Where <thing-to-sign> is the binary or shared library to be signed \n\
and <options> are one of:\n\
    --help                -- ths message\n\
    --platform OE         -- execute an application within the libos\n\
    --target <filename>   -- target to be signed, OE Enclave when platform is OE\n\
    --rootfs <filename>   -- path to CPIO archive file\n\
    --pem_file <filename> -- filename of private RSA key in PEM format\n\
    --config_file <filename>   -- filename of signing configuration\n\
\n\
"

static const char *help_present = NULL;
static const char *platform = NULL;
static const char *target = NULL;
static const char *rootfs_file = NULL;
static const char *pem_file = NULL;
static const char *config_file = NULL;

static const char *help_options[] = {"--help", "-h"};
static const char *platform_options[] = {"--platform", "-p"};
static const char *target_options[] = {"--target", "-t"};
static const char *rootfs_options[] = {"--rootfs", "-r"};
static const char *pem_options[] = {"--pem_file", "-k"};
static const char *config_options[] = {"--config_file", "-c"};

struct _option option_list[] = 
{
    // {names array}, names_count, num_extra_param, extra_param, extra_param_required
    {help_options, sizeof(help_options)/sizeof(const char *), 0, &help_present, 0},
    {platform_options, sizeof(platform_options)/sizeof(const char *), 1, &platform, 1},
    {target_options, sizeof(target_options)/sizeof(const char *), 1, &target, 1},
    {rootfs_options, sizeof(rootfs_options)/sizeof(const char *), 1, &rootfs_file, 1},
    {pem_options, sizeof(pem_options)/sizeof(const char *), 1, &pem_file, 1},
    {config_options, sizeof(config_options)/sizeof(const char *), 1, &config_file, 1}
};
struct _options options =
{
    option_list,
    sizeof(option_list)/sizeof(struct _option)
};

int _sign(int argc, const char* argv[])
{
    int ret = 0;
    const region_details *details;
    const mode_t mode =
        S_IROTH|S_IXOTH|S_IXGRP|S_IWGRP|S_IRGRP|S_IXUSR|S_IWUSR|S_IRUSR;

    // We are in the right operation, right?
    assert(strcmp(argv[1], "sign") == 0);

    // Parse the extra options and validate they exist when required
    if ((ret = parse_options(argc, argv, 2, &options)) != 0)
    {
        _err("Failed to parse options.");
    }

    if ((details = create_region_details(target, rootfs_file)) == NULL)
    {
        _err("Creating region data failed.");
    }

    char dirname[PATH_MAX] = "app.signed";
    char bindir[PATH_MAX];
    char libdir[PATH_MAX];
    char oelibdir[PATH_MAX];
    char libosenc[PATH_MAX];
    char libosenc_signed[PATH_MAX];
    char liboscrt[PATH_MAX];
    char liboskernel[PATH_MAX];
    char libos[PATH_MAX];
    char rootfs[PATH_MAX];

    /* Form destination directory paths */
    snprintf(bindir, PATH_MAX, "%s/bin", dirname);
    snprintf(libdir, PATH_MAX, "%s/lib", dirname);
    snprintf(oelibdir, PATH_MAX, "%s/lib/openenclave", dirname);

    /* Form destination file paths */
    snprintf(libos, PATH_MAX, "%s/libos", bindir);
    snprintf(rootfs, PATH_MAX, "%s/rootfs", dirname);
    snprintf(libosenc, PATH_MAX, "%s/libosenc.so", oelibdir);
    snprintf(libosenc_signed, PATH_MAX, "%s/libosenc.so.signed", oelibdir);
    snprintf(liboscrt, PATH_MAX, "%s/liboscrt.so", libdir);
    snprintf(liboskernel, PATH_MAX, "%s/liboskernel.so", libdir);

    // Make a directory for all the bits part of the signing
    if (libos_mkdirhier(dirname, mode) != 0)
        _err("Failed to create directory \"%s\".", dirname);

    // Make the bin directory */
    if (libos_mkdirhier(bindir, mode) != 0)
        _err("Failed to create directory \"%s\".\n", bindir);

    // Make the lib directory */
    if (libos_mkdirhier(libdir, mode) != 0)
        _err("Failed to create directory \"%s\".\n", libdir);

    // Make the openenclave/lib directory */
    if (libos_mkdirhier(oelibdir, mode) != 0)
        _err("Failed to create directory \"%s\".\n", oelibdir);

    // Copy crt into signing enc directory
    if (libos_copy_file(details->crt_path, liboscrt) != 0)
        _err("Failed to copy \"%s\" to \"%s\"", details->crt_path, liboscrt);

    // Copy kernel into signing directory
    if (libos_copy_file(details->kernel_path, liboskernel) != 0)
        _err("Failed to copy \"%s\" to \"%s\"", details->crt_path, liboskernel);

    // Copy libos tool into signing directory
    if (libos_copy_file(argv[0], libos) != 0)
        _err("Failed to copy \"%s\" to \"%s\"", argv[0], libos);

    if (chmod(libos, mode) != 0)
        _err("Failed to change executable permissions on \"%s\"", libos);

    // Copy rootfs into signing directory
    if (libos_copy_file(rootfs_file, rootfs) != 0)
        _err("Failed to copy \"%s\" to \"%s\"", rootfs_file, rootfs);

    // Finally (we need this path also for actual signing!)
    // Copy enclave shared library to signing enclave directory
    if (libos_copy_file(details->enc_path, libosenc) != 0)
        _err("Failed to copy \"%s\" to \"%s\"", details->enc_path, libosenc);

    // Initiate signing with extracted parameters
    // Watch out! Previous to_path needs to be the enclave binary!
    if (oesign(libosenc, NULL /*no config yet!*/, pem_file, NULL, NULL, NULL, NULL, NULL) != 0)
    {
        _err("Failed to sign \"%s\"", libosenc);
    }

    // Delete the unsigned enclave file
    if (unlink(libosenc) != 0)
        _err("Failed to delete \"%s\"", libosenc);

    if (rename (libosenc_signed, libosenc) != 0)
        _err("Failed to rename \"%s\" to \"%s\"", libosenc_signed, libosenc);

    return 0;
}
