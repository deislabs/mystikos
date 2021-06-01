// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <myst/getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include <myst/elf.h>
#include <myst/file.h>
#include <myst/strings.h>
#include <myst/types.h>
#include <openenclave/host.h>
#include "../config.h"
#include "archive.h"
#include "myst_u.h"
#include "regions.h"
#include "utils.h"

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

#define USAGE_SIGN \
    "\
\n\
Usage: %s sign-sgx <rootfs_path> <pem_file> <config_file> [options] \n\
\n\
Where:\n\
    sign-sgx                    -- This operation signs and measures all\n\
                                   SGX enclave loadable components and puts\n\
                                   then in the target directory\n\
    <rootfs_path>               -- Path to CPIO archive file of the\n\
                                   application directory\n\
    <pem_file>                  -- Filename of private RSA key in PEM format\n\
    <config_file>               -- Filename of signing configuration\n\
\n\
and <options> are one of:\n\
    --help                      -- This message\n\
    --outdir <path>             -- optional output directory path. If not\n\
                                   specified goes into the configurations\n\
                                   <appdir>.signed directpry\n\
\n\
"

static const char* user_sign_dir = NULL;

int copy_files_to_signing_directory(
    const char* sign_dir,
    const char* program_file,
    const char* rootfs_file,
    const char* archive_file,
    const char* config_file,
    const region_details* details)
{
    char scratch_path[PATH_MAX];
    const mode_t mode = S_IROTH | S_IXOTH | S_IXGRP | S_IWGRP | S_IRGRP |
                        S_IXUSR | S_IWUSR | S_IRUSR;

    // create bin directory
    if (snprintf(scratch_path, PATH_MAX, "%s/bin", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/bin", sign_dir);
    }
    if ((mkdir(scratch_path, mode) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", scratch_path);
    }

    // create an enclave directory
    if (snprintf(scratch_path, PATH_MAX, "%s/lib", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/lib", sign_dir);
    }
    if ((mkdir(scratch_path, mode) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", scratch_path);
    }
    // create an enclave directory
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/openenclave", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/lib/openenclave", sign_dir);
    }
    if ((mkdir(scratch_path, mode) != 0) && (errno != EEXIST))
    {
        _err("Failed to create directory \"%s\".", scratch_path);
    }

    // Copy crt into signing enc directory
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystcrt.so", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/lib/libmystcrt.so", sign_dir);
    }
    if (myst_copy_file(details->crt.path, scratch_path) != 0)
    {
        _err(
            "Failed to copy \"%s\" to \"%s\"", details->crt.path, scratch_path);
    }

    // Copy kernel into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystkernel.so", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/lib/libmystkernel.so", sign_dir);
    }
    if (myst_copy_file(details->kernel.path, scratch_path) != 0)
    {
        _err(
            "Failed to copy \"%s\" to \"%s\"", details->crt.path, scratch_path);
    }

    // Copy myst tool into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/myst", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/bin/myst", sign_dir);
    }
    if (myst_copy_file(program_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", program_file, scratch_path);
    }
    if (chmod(scratch_path, mode) != 0)
    {
        _err("Failed to change executable permissions on \"%s\"", scratch_path);
    }

    // Copy rootfs into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/rootfs", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/rootfs", sign_dir);
    }
    if (myst_copy_file(rootfs_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", rootfs_file, scratch_path);
    }

    // Copy archive into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/archive", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/archive", sign_dir);
    }
    if (myst_copy_file(archive_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", archive_file, scratch_path);
    }

    // Copy configuration into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/config.json", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/config.json", sign_dir);
    }
    if (myst_copy_file(config_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", config_file, scratch_path);
    }

    // Copy enclave shared library to signing enclave directory
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/lib/openenclave/mystenc.so", sign_dir);
    }
    if (myst_copy_file(details->enc.path, scratch_path) != 0)
    {
        _err(
            "Failed to copy \"%s\" to \"%s\"", details->enc.path, scratch_path);
    }

    return 0;
}

int add_config_to_enclave(const char* sign_dir, const char* config_path)
{
    char scratch_path[PATH_MAX];
    elf_t elf = {0};
    void* config_data;
    size_t config_size;
    if (myst_load_file(config_path, &config_data, &config_size) != 0)
    {
        _err("Failed to load config file %s", config_path);
    }

    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/lib/openenclave/mystenc.so", sign_dir);
    }

    if (elf_load(scratch_path, &elf) != 0)
    {
        _err("Failed to load ELF image %s", scratch_path);
    }
    if (elf_add_section(
            &elf, ".mystconfig", SHT_PROGBITS, config_data, config_size) != 0)
    {
        _err("Failed to add configuration to enclave elf image");
    }
    if (myst_write_file(scratch_path, elf.data, elf.size) != 0)
    {
        _err("File to save final signed image: %s", scratch_path);
    }

    elf_unload(&elf);
    free(config_data);

    return 0;
}

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = myst_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

// myst sign <rootfs_path> <pem_file> <config_file>
int _sign(int argc, const char* argv[])
{
    const region_details* details;
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];
    char archive_buf[PATH_MAX];
    const char* archive = NULL;
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    static const size_t max_roothashes = 128;
    const char* roothashes[max_roothashes];
    size_t num_roothashes = 0;
    const char* signing_engine_key = NULL;
    const char* signing_engine_name = NULL;
    const char* signing_engine_path = NULL;

    // We are in the right operation, right?
    assert(
        (strcmp(argv[1], "sign") == 0) || (strcmp(argv[1], "sign-sgx") == 0));

    if (_getopt(&argc, argv, "--archive", &archive) != 0)
    {
        get_archive_options(
            &argc,
            argv,
            pubkeys,
            max_pubkeys,
            &num_pubkeys,
            roothashes,
            max_roothashes,
            &num_roothashes);
    }

    _getopt(&argc, argv, "--signing-engine-key", &signing_engine_key);
    _getopt(&argc, argv, "--signing-engine-name", &signing_engine_name);
    _getopt(&argc, argv, "--signing-engine-path", &signing_engine_path);
    if ((signing_engine_key || signing_engine_name || signing_engine_path) &&
        (!signing_engine_key || !signing_engine_name || !signing_engine_path))
    {
        fprintf(
            stderr,
            "If using a signing engine all three parameters are required: "
            "--signing-engine-key, "
            "--signing-engine-name and --signing-engine-path\n");
        fprintf(stderr, USAGE_SIGN, argv[0]);
        return -1;
    }

    // validate parameters and parse the extra options and validate they exist
    // when required
    if ((argc < 5) || (cli_getopt(&argc, argv, "--help", NULL) == 0) ||
        (cli_getopt(&argc, argv, "-h", NULL) == 0))
    {
        fprintf(stderr, USAGE_SIGN, argv[0]);
        return -1;
    }
    if ((cli_getopt(&argc, argv, "--outdir", &user_sign_dir) == 0) ||
        (cli_getopt(&argc, argv, "-d", &user_sign_dir) == 0))
    {
        // we have the optional signing dir
    }

    const char* program_file = get_program_file();
    const char* rootfs_file = argv[2];
    const char* pem_file = argv[3];
    const char* config_file = argv[4];
    const char* target = NULL;  // Extracted from config file
    const char* appname = NULL; // extracted from target
    char temp_oeconfig_file[PATH_MAX];
    char sign_dir[PATH_MAX];
    config_parsed_data_t parsed_data = {0};

    // Load the configuration file and generate oe config file
    if (parse_config_from_file(config_file, &parsed_data) != 0)
    {
        _err(
            "Failed to parse configuration file from Mystikos configuration "
            "file %s",
            config_file);
    }

    target = parsed_data.application_path;
    if ((target == NULL) || (target[0] != '/'))
    {
        _err(
            "target in config file must be fully qualified path within rootfs");
    }

    appname = strrchr(target, '/');
    if (appname == NULL)
    {
        _err("Failed to get appname from target path");
    }
    appname++;
    if (*appname == '\0')
    {
        _err("Failed to get appname from target path");
    }

    // Do we need to create our own signing directory?
    if (user_sign_dir == NULL)
    {
        if (snprintf(sign_dir, PATH_MAX, "%s.signed", appname) >= PATH_MAX)
        {
            _err("Signing directory path to long: %s.signed", appname);
        }
        if (mkdir(sign_dir, 0777) != 0)
        {
            _err("Failed to create signing directory: %s", sign_dir);
        }
    }
    else
    {
        if (snprintf(sign_dir, PATH_MAX, "%s", user_sign_dir) >= PATH_MAX)
        {
            _err("Signing directory path to long: %s", sign_dir);
        }
    }

    if (snprintf(
            temp_oeconfig_file, PATH_MAX, "%s/oeconfig-XXXXXX", sign_dir) >=
        PATH_MAX)
    {
        _err("OE config file path to long: %s/oeconfig-XXXXXX", sign_dir);
    }

    int fd = mkstemp(temp_oeconfig_file);
    if (fd < 0)
        _err("Failed to create temporary file for OE configuration");

    if (write_oe_config_fd(fd, &parsed_data) != 0)
    {
        unlink(temp_oeconfig_file);
        close(fd);
        _err(
            "Failed to generate OE configuration file from Mystikos "
            "configuration "
            "file %s",
            config_file);
    }
    close(fd);

    if (!archive)
    {
        create_archive(
            pubkeys, num_pubkeys, roothashes, num_roothashes, archive_buf);
        archive = archive_buf;
    }

    // Setup all the regions
    if ((details = create_region_details_from_files(
             target,
             rootfs_file,
             archive,
             config_file,
             parsed_data.heap_pages)) == NULL)
    {
        unlink(temp_oeconfig_file);
        _err("Creating region data failed.");
    }

    if (copy_files_to_signing_directory(
            sign_dir,
            program_file,
            rootfs_file,
            archive,
            config_file,
            details) != 0)
    {
        unlink(temp_oeconfig_file);
        _err("Failed to copy files to signing directory");
    }

    if (add_config_to_enclave(sign_dir, config_file) != 0)
    {
        unlink(temp_oeconfig_file);
        _err("Failed to add configuration to enclave");
    }

    // Initiate signing with extracted parameters
    // Watch out! Previous to_path needs to be the enclave binary!
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            sign_dir) >= PATH_MAX)
    {
        unlink(temp_oeconfig_file);
        _err("File path to long: %s/lib/openenclave/mystenc.so", sign_dir);
    }

    if (oesign(
            scratch_path,
            temp_oeconfig_file,
            pem_file,
            NULL,
            NULL,
            signing_engine_name,
            signing_engine_path,
            signing_engine_key) != 0)
    {
        unlink(temp_oeconfig_file);
        _err("Failed to sign \"%s\"", scratch_path);
    }

    // delete temporary oe config file
    if (unlink(temp_oeconfig_file) != 0)
    {
        _err("Failed to remove temporary OE config file");
    }

    // Delete the unsigned enclave file
    if (unlink(scratch_path) != 0)
    {
        _err("Failed to delete \"%s\"", scratch_path);
    }

    if (snprintf(
            scratch_path2,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so.signed",
            sign_dir) >= PATH_MAX)
    {
        _err(
            "File path to long: %s/lib/openenclave/mystenc.so.signed",
            sign_dir);
    }
    if (rename(scratch_path2, scratch_path) != 0)
    {
        _err("Failed to rename \"%s\" to \"%s\"", scratch_path2, scratch_path);
    }

    return 0;
}
