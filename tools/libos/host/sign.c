// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <libos/elf.h>
#include <libos/file.h>
#include <libos/strings.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libos/types.h>
#include <unistd.h>
#include "../config.h"
#include "libos_u.h"
#include "parse_options.h"
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
Usage: %s sign <rootfs_path> <pem_file> <config_file> [options] \n\
\n\
This operation signs all enclave components and puts then in the target directory\n\
\n\
Where:\n\
    <target_path_within_appdir> -- The application path relative to start of appdir \n\
    <rootfs_path>               -- Path to CPIO archive file \n\
    <pem_file>                  -- Filename of private RSA key in PEM format \n\
    <config_file>               -- Filename of signing configuration \n\
and <options> are one of:\n\
    --help                -- This message\n\
    --platform <platform> -- Platform for which this is being signed for. Default='OE'\n\
    --app-name <name>     -- Application name. Default='app'. \n\
                             This is used for the target signing directory which will be\n\
                             <name>.signed\n\
\n\
"

static const char* help_present = NULL;
static const char* platform = "OE";
static const char* user_sign_dir = NULL;

static const char* help_options[] = {"--help", "-h"};
static const char* platform_options[] = {"--platform", "-p"};
static const char* sign_dir_options[] = {"--ourdir", "-d"};

static struct _option option_list[] = {
    // {names array}, names_count, num_extra_param, extra_param,
    // extra_param_required
    {help_options,
     sizeof(help_options) / sizeof(const char*),
     0,
     &help_present,
     0},
    {platform_options,
     sizeof(platform_options) / sizeof(const char*),
     1,
     &platform,
     0},
    {sign_dir_options,
     sizeof(sign_dir_options) / sizeof(const char*),
     1,
     &user_sign_dir,
     0}};
static struct _options options = {option_list,
                                  sizeof(option_list) / sizeof(struct _option)};

int copy_files_to_signing_directory(
    const char* sign_dir,
    const char* program_file,
    const char* rootfs_file,
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
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/liboscrt.so", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/lib/liboscrt.so", sign_dir);
    }
    if (libos_copy_file(details->crt.path, scratch_path) != 0)
    {
        _err(
            "Failed to copy \"%s\" to \"%s\"", details->crt.path, scratch_path);
    }

    // Copy kernel into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/liboskernel.so", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/lib/liboskernel.so", sign_dir);
    }
    if (libos_copy_file(details->kernel.path, scratch_path) != 0)
    {
        _err(
            "Failed to copy \"%s\" to \"%s\"", details->crt.path, scratch_path);
    }

    // Copy libos tool into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/libos", sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/bin/libos", sign_dir);
    }
    if (libos_copy_file(program_file, scratch_path) != 0)
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
    if (libos_copy_file(rootfs_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", rootfs_file, scratch_path);
    }

    // Copy configuration into signing directory
    if (snprintf(scratch_path, PATH_MAX, "%s/config.json", sign_dir) >=
        PATH_MAX)
    {
        _err("File path to long: %s/config.json", sign_dir);
    }
    if (libos_copy_file(config_file, scratch_path) != 0)
    {
        _err("Failed to copy \"%s\" to \"%s\"", config_file, scratch_path);
    }

    // Copy enclave shared library to signing enclave directory
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/libosenc.so",
            sign_dir) >= PATH_MAX)
    {
        _err("File path to long: %s/lib/openenclave/libosenc.so", sign_dir);
    }
    if (libos_copy_file(details->enc.path, scratch_path) != 0)
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
    if (libos_load_file(config_path, &config_data, &config_size) != 0)
    {
        _err("Failed to load config file %s", config_path);
    }

    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/libosenc.so",
            sign_dir) >= PATH_MAX)
    {
        _err(
            "File path to long: %s/lib/openenclave/libosenc.so",
            sign_dir);
    }

    if (elf_load(scratch_path, &elf) != 0)
    {
        _err("Failed to load ELF image %s", scratch_path);
    }
    if (elf_add_section(
            &elf, ".libosconfig", SHT_PROGBITS, config_data, config_size) != 0)
    {
        _err("Failed to add configuration to enclave elf image");
    }
    if (libos_write_file(scratch_path, elf.data, elf.size) != 0)
    {
        _err("File to save final signed image: %s", scratch_path);
    }

    elf_unload(&elf);
    free(config_data);

    return 0;
}

// libos sign <rootfs_path> <pem_file> <config_file>
int _sign(int argc, const char* argv[])
{
    const region_details* details;
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];

    // We are in the right operation, right?
    assert(strcmp(argv[1], "sign") == 0);

    // validate parameters and parse the extra options and validate they exist
    // when required
    if ((argc < 5) || (parse_options(argc, argv, 5, &options) != 0) ||
        help_present)
    {
        fprintf(stderr, USAGE_SIGN, argv[0]);
        return -1;
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
            "Failed to parse configuration file from LibOS configuration "
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

    // Need to calculate the OE user memory which in our case
    // means enclave binary, the kernel and the rootfs.
    // We know the size of the rootfs through inspection so we add a bit
    // to cover the other required space.
    struct stat st;
    stat(rootfs_file, &st);

    parsed_data.oe_num_heap_pages = (st.st_size + (5 * 1024 * 1024)) / LIBOS_PAGE_SIZE;

    if (write_oe_config_fd(fd, &parsed_data) != 0)
    {
        unlink(temp_oeconfig_file);
        close(fd);
        _err(
            "Failed to generate OE configuration file from LibOS configuration "
            "file %s",
            config_file);
    }
    close(fd);

    // Setup all the regions
    if ((details = create_region_details_from_files(
             target, rootfs_file, config_file, parsed_data.user_pages)) == NULL)
    {
        unlink(temp_oeconfig_file);
        _err("Creating region data failed.");
    }

    if (copy_files_to_signing_directory(
            sign_dir, program_file, rootfs_file, config_file, details) != 0)
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
            "%s/lib/openenclave/libosenc.so",
            sign_dir) >= PATH_MAX)
    {
        unlink(temp_oeconfig_file);
        _err("File path to long: %s/lib/openenclave/libosenc.so", sign_dir);
    }

    if (oesign(
            scratch_path,
            temp_oeconfig_file,
            pem_file,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL) != 0)
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
            "%s/lib/openenclave/libosenc.so.signed",
            sign_dir) >= PATH_MAX)
    {
        _err(
            "File path to long: %s/lib/openenclave/libosenc.so.signed",
            sign_dir);
    }
    if (rename(scratch_path2, scratch_path) != 0)
    {
        _err("Failed to rename \"%s\" to \"%s\"", scratch_path2, scratch_path);
    }

    return 0;
}
