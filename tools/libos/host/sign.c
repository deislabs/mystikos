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

int _sign_file_copy(
    const char *from_file, 
    char to_file[PATH_MAX], size_t start_point,
    const char *append_file)
{
    FILE *source = NULL;
    FILE *target = NULL;
    size_t read;
    char buffer[1024];
    int ret = -1;

    strcpy(to_file+start_point, append_file);

    source = fopen(from_file, "r");
    if (source == NULL)
    {
        goto done;
    }
    target = fopen(to_file, "w");
    if (target == NULL)
    {
        goto done;
    }

    do
    {
        read = fread(buffer, 1, sizeof(buffer), source);
        if (read != 0)
        {
            if (fwrite(buffer, 1, read, target) != read)
            {
                break;
            }
        }
    } while (read != 0);

    if ((feof(source) != 0) || (ferror(target) != 0))
    {
        ret = -1;
    }

    ret = 0;

done:
    if (source)
    {
        fclose(source);
    }
    if (target)
    {
        fclose(target);
    }
    return ret;
}

int _sign(int argc, const char* argv[])
{
    int ret = 0;
    const region_details *details;

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

    char to_filename[PATH_MAX] = "app.signed";
    size_t appdir_len;

    // Make a directory for all the bits part of the signing
    if ((mkdir(to_filename, S_IROTH|S_IXOTH|S_IXGRP|S_IWGRP|S_IRGRP|S_IXUSR|S_IWUSR|S_IRUSR) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", to_filename);
    }

    appdir_len = strlen(to_filename);

    // Under that create an enclave directory
    strcpy(to_filename+appdir_len, "/enc");
    if ((mkdir(to_filename, S_IROTH|S_IXOTH|S_IXGRP|S_IWGRP|S_IRGRP|S_IXUSR|S_IWUSR|S_IRUSR) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", to_filename);
    }

    // want the initial destination path to include slash
    appdir_len++;

    // Copy crt into signing enc directory
    if (_sign_file_copy(details->crt_path, to_filename, appdir_len, "enc/liboscrt.so") != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", details->crt_path, to_filename);
    }

    // Copy kernel into signing directory
    if (_sign_file_copy(details->kernel_path, to_filename, appdir_len, "liboskernel.so") != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", details->crt_path, to_filename);
    }

    // Copy libos tool into signing directory
    if (_sign_file_copy(argv[0], to_filename, appdir_len, "libos") != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", argv[0], to_filename);
    }
    if (chmod(to_filename, S_IROTH|S_IXOTH|S_IXGRP|S_IWGRP|S_IRGRP|S_IXUSR|S_IWUSR|S_IRUSR) != 0)
    {
        _err("Failed to change executable permissions on \"%s\"", to_filename);
    }

    // Copy rootfs into signing directory
    if (_sign_file_copy(rootfs_file, to_filename, appdir_len, "rootfs") != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", rootfs_file, to_filename);
    }

    // Finally (we need this path also for actual signing!)
    // Copy enclave shared library to signing enclave directory
    if (_sign_file_copy(details->enc_path, to_filename, appdir_len, "enc/libosenc.so") != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", details->enc_path, to_filename);
    }

    // Initiate signing with extracted parameters
    // Watch out! Previous to_path needs to be the enclave binary!
    if (oesign(to_filename, NULL /*no config yet!*/, pem_file, NULL, NULL, NULL, NULL, NULL) != 0)
    {
        _err("Failed to sign \"%s\"", to_filename);
    }

    //Delete the unsigned enclave file
    if (unlink("app.signed/enc/libosenc.so") != 0)
    {
        _err("Failed to delete \"%s\"", to_filename);
    }

    if (rename ("app.signed/enc/libosenc.so.signed", "app.signed/enc/libosenc.so") != 0)
    {
        _err("Failed to rename \"%s\" to \"%s\"", "app.signed/enc/libosenc.so.signed", "app.signed/enc/libosenc.so");
    }

    return 0;
}
