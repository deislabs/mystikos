// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <myst/types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#include <myst/elf.h>
#include <myst/getopt.h>
#include <myst/strings.h>
#include <openenclave/host.h>

#include "../config.h"
#include "archive.h"
#include "cpio.h"
#include "exec.h"
#include "myst/file.h"
#include "myst_args.h"
#include "regions.h"
#include "sign.h"
#include "utils.h"

_Static_assert(PAGE_SIZE == 4096, "");

#define USAGE_PACKAGE \
    "\
\n\
Usage:\n\
    %s package-sgx [options] <app_dir> <pem_file> <config>\n\
    %s package-sgx [options] <pem_file> <config>\n\
\n\
Where:\n\
    package-sgx -- create an executable package to run on the SGX platform\n\
                   from an application directory, package configuration and\n\
                   system files, signing and measuring all enclave resident\n\
                   pieces during in the process\n\
    <app_dir>   -- application directory with files for root filesystem\n\
    <pem_file>  -- private key to sign and measure SGX enclave files\n\
    <config>    -- configuration for signing and application runtime\n\
\n\
and <options> are one of:\n\
    --help                -- this message\n\
    --pubkey=pem_file     -- trust disks signed by this key (repeatable)\n\
    --roothash=ascii_file -- trust disks with this roothash (repeatable)\n\
\n\
"

static int _add_image_to_elf_section(
    elf_t* elf,
    const char* path,
    const char* section_name)
{
    void* image = NULL;
    size_t image_length = 0;
    int ret = -1;

    if (myst_load_file(path, &image, &image_length) != 0)
    {
        fprintf(stderr, "Failed to load %s", path);
        goto done;
    }
    if (elf_add_section(elf, section_name, SHT_PROGBITS, image, image_length) !=
        0)
    {
        fprintf(stderr, "Failed to add %s to elf image", path);
        goto done;
    }
    free(image);

    ret = 0;

done:
    return ret;
}

#define DIR_MODE                                                          \
    S_IROTH | S_IXOTH | S_IXGRP | S_IWGRP | S_IRGRP | S_IXUSR | S_IWUSR | \
        S_IRUSR

// myst package <app_dir> <pem_file> <config> [options]
int _package(int argc, const char* argv[])
{
    int ret = -1;
    const char* app_dir = NULL;
    const char* pem_file = NULL;
    const char* config_file = NULL;
    const char* target = NULL;  // Extracted from config
    const char* appname = NULL; // Extracted from target
    char* tmp_dir = NULL;
    char dir_template[] = "/tmp/mystXXXXXX";
    char rootfs_file[PATH_MAX];
    char archive_file[PATH_MAX];
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];
    config_parsed_data_t parsed_data = {0};
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    static const size_t max_roothashes = 128;
    const char* roothashes[max_roothashes];
    size_t num_roothashes = 0;

    /* Get --pubkey=filename and --roothash=filename options */
    get_archive_options(
        &argc,
        argv,
        pubkeys,
        max_pubkeys,
        &num_pubkeys,
        roothashes,
        max_roothashes,
        &num_roothashes);

    if ((argc < 4) || (cli_getopt(&argc, argv, "--help", NULL) == 0) ||
        (cli_getopt(&argc, argv, "-h", NULL) == 0))
    {
        fprintf(stderr, USAGE_PACKAGE, argv[0], argv[0]);
        goto done;
    }

    // We are in the right operation, right?
    assert(
        (strcmp(argv[1], "package") == 0) ||
        (strcmp(argv[1], "package-sgx") == 0));

    if (argc == 5)
    {
        app_dir = argv[2];
        pem_file = argv[3];
        config_file = argv[4];
    }
    else if (argc == 4)
    {
        app_dir = NULL;
        pem_file = argv[2];
        config_file = argv[3];
    }

    create_archive(
        pubkeys, num_pubkeys, roothashes, num_roothashes, archive_file);

    tmp_dir = mkdtemp(dir_template);
    if (tmp_dir == NULL)
    {
        fprintf(stderr, "Failed to create temporary directory in /tmp\n");
        goto done;
    }

    if (snprintf(rootfs_file, PATH_MAX, "%s/rootfs.pkg", tmp_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path too long? %s/rootfs.pkg\n", tmp_dir);
        goto done;
    }

    if (app_dir)
    {
        const char* mkcpio_args[] = {argv[0], // ..../myst
                                     "mkcpio",
                                     app_dir,
                                     rootfs_file};

        if (_mkcpio(
                sizeof(mkcpio_args) / sizeof(mkcpio_args[0]), mkcpio_args) != 0)
        {
            fprintf(
                stderr,
                "Failed to create root filesystem \"%s\" from directory "
                "\"%s\"\n",
                rootfs_file,
                app_dir);
            goto done;
        }
    }
    else
    {
        /* generate a dummy CPIO rootfs with one page of zero bytes */
        int fd;
        uint8_t page[PAGE_SIZE];
        const int flags = O_CREAT | O_WRONLY | O_TRUNC;

        if ((fd = open(rootfs_file, flags, 0666)) < 0)
            _err("failed to create temporary file");

        memset(page, 0, sizeof(page));

        if (write(fd, page, sizeof(page)) != sizeof(page))
            _err("failed to create file: %s", rootfs_file);

        close(fd);
    }

    if (parse_config_from_file(config_file, &parsed_data) != 0)
    {
        fprintf(
            stderr,
            "Failed to generate OE configuration file %s from Mystikos "
            "configuration file %s\n",
            scratch_path2,
            config_file);
        goto done;
    }

    target = parsed_data.application_path;
    if ((target == NULL) || (target[0] != '/'))
    {
        fprintf(
            stderr,
            "target in config file must be fully qualified path within rootfs");
        goto done;
    }

    appname = strrchr(target, '/');
    if (appname == NULL)
    {
        fprintf(stderr, "Failed to get appname from target path");
        goto done;
    }
    appname++;
    if (*appname == '\0')
    {
        fprintf(stderr, "Failed to get appname from target path");
        goto done;
    }

    // sign the enclave and measure all regions of enclave
    const char* sign_args[] = {argv[0],
                               "sign",
                               rootfs_file,
                               pem_file,
                               config_file,
                               "--archive",
                               archive_file,
                               "--outdir",
                               tmp_dir};

    // Sign and copy everything into app.signed directory
    if (_sign(sizeof(sign_args) / sizeof(sign_args[0]), sign_args) != 0)
    {
        fprintf(stderr, "Failed to sign enclave file");
        goto done;
    }

    // Now package everything up in a single binary
    elf_t elf;

    memset(&elf, 0, sizeof(elf));

    // First load the myst application so we can add the other components
    // as named sections in the image
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/myst", tmp_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/myst", tmp_dir);
        goto done;
    }
    if (elf_load(scratch_path, &elf) != 0)
    {
        fprintf(stderr, "Failed to load %s/bin/myst", tmp_dir);
        goto done;
    }

    // Add the enclave to myst
    if (snprintf(
            scratch_path, PATH_MAX, "%s/lib/openenclave/mystenc.so", tmp_dir) >=
        PATH_MAX)
    {
        fprintf(
            stderr,
            "File path to long: %s/openenclave/lib/mystenc.so",
            tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".mystenc") != 0)
    {
        fprintf(
            stderr,
            "Failed to add %s to enclave section .mystenc",
            scratch_path);
        goto done;
    }

    // Add the enclave CRT to myst
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystcrt.so", tmp_dir) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/lib/libmystcrt.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libmystcrt") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .lioscrt",
            scratch_path);
        goto done;
    }

    // Add the kernel to myst
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystkernel.so", tmp_dir) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/lib/libmystkernel.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libmystkernel") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .libmystkernel",
            scratch_path);
        goto done;
    }

    // Add the rootfs to myst
    if (_add_image_to_elf_section(&elf, rootfs_file, ".mystrootfs") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .mystrootfs",
            rootfs_file);
        goto done;
    }

    // Add the archive to myst
    if (_add_image_to_elf_section(&elf, archive_file, ".mystarchive") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .mystarchive",
            archive_file);
        goto done;
    }

    // Add the config to myst
    if (_add_image_to_elf_section(&elf, config_file, ".mystconfig") != 0)
    {
        fprintf(
            stderr,
            "Failed to add image %s to enclave section .mystconfig",
            config_file);
        goto done;
    }

    // Save new elf image back
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }
    int fd = open(scratch_path, O_WRONLY | O_CREAT | O_TRUNC, 0774);
    if (fd == 0)
    {
        fprintf(
            stderr,
            "Failed to epn file to write final binary image back to %s",
            scratch_path);
        goto done;
    }
    if (myst_write_file_fd(fd, elf.data, elf.size) != 0)
    {
        close(fd);
        fprintf(
            stderr,
            "File to save final binary image back to: %s",
            scratch_path);
        goto done;
    }
    close(fd);

    elf_unload(&elf);

    //
    // Move the final file to the proper destination
    //
    // Create destination directory myst/bin
    if ((mkdir("myst", 0775) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to make destination directory myst\n");
        goto done;
    }
    if ((mkdir("myst/bin", 0775) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to make destination directory myst/bin\n");
        goto done;
    }

    // Destination filename
    if (snprintf(scratch_path, PATH_MAX, "myst/bin/%s", appname) >= PATH_MAX)
    {
        fprintf(stderr, "File path to long: myst/bin/%s", appname);
        goto done;
    }

    // Source filename
    if (snprintf(scratch_path2, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        fprintf(stderr, "File path to long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }

    if (myst_copy_file(scratch_path2, scratch_path) != 0)
    {
        fprintf(
            stderr,
            "Failed to copy final package from %s to %s",
            scratch_path2,
            scratch_path);
        goto done;
    }

    ret = 0;

done:

    if (tmp_dir)
        remove_recursive(tmp_dir);

    return ret;
}

/* if this is the null rootfs (one page full of zeros) */
static bool _is_null_rootfs(const void* s, size_t n)
{
    const uint8_t* p = s;

    if (!s || n != PAGE_SIZE)
        return false;

    while (n--)
    {
        if (*p++)
            return false;
    }

    return true;
}

// <app_name> [app args]
int _exec_package(
    int argc,
    const char* argv[],
    const char* envp[],
    const char* executable)
{
    char full_app_path[PATH_MAX];
    char* app_dir = NULL;
    char* app_name = NULL;
    char scratch_path[PATH_MAX];
    const region_details* details = NULL;
    unsigned char* buffer = NULL;
    size_t buffer_length = 0;
    elf_image_t myst_elf = {0};
    int elf_loaded = 0;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct myst_options options = {0};
    char* config_buffer = NULL;
    size_t config_size = 0;
    char unpack_dir_template[] = "/tmp/mystXXXXXX";
    char* unpack_dir = NULL;
    int ret = -1;
    const char** exec_args = NULL;
    const size_t max_threads = 0;

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (cli_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            cli_getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }
    }

    /* Get --trace option */
    if (cli_getopt(&argc, argv, "--trace-errors", NULL) == 0 ||
        cli_getopt(&argc, argv, "--etrace", NULL) == 0)
    {
        options.trace_errors = true;
    }

    /* Get --shell option */
    if (cli_getopt(&argc, argv, "--shell", NULL) == 0)
        options.shell_mode = true;

    if (!realpath(argv[0], full_app_path))
    {
        fprintf(stderr, "Invalid path %s\n", argv[0]);
        goto done;
    }
    app_dir = full_app_path;
    app_name = strrchr(full_app_path, '/');
    *app_name = '\0';
    app_name++;

    // Create a directory to unpack the package into, and to run from,
    // as well as the directory structure we need
    if ((unpack_dir = mkdtemp(unpack_dir_template)) == NULL)
    {
        fprintf(stderr, "Failed to create unpack directory\n");
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib", unpack_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path %s/lib is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/bin", unpack_dir) >= PATH_MAX)
    {
        fprintf(stderr, "File path %s/bin is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/openenclave", unpack_dir) >=
        PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        fprintf(stderr, "Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }

    // Load main executable so we can extract sections
    if (elf_image_load(get_program_file(), &myst_elf) != 0)
    {
        fprintf(stderr, "failed to load myst image: %s\n", get_program_file());
        goto done;
    }
    elf_loaded = 1;

    // copy executable to unpack directory where we will run it from
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", unpack_dir, app_name) >=
        PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/bin/%s is too long\n", unpack_dir, app_name);
        goto done;
    }
    if (myst_copy_file(get_program_file(), scratch_path) < 0)
    {
        fprintf(
            stderr,
            "Failed to copy %s to %s\n",
            get_program_file(),
            scratch_path);
        goto done;
    }

    // Make enclave directory and extract enclave into it
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            unpack_dir) >= PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }
    if (elf_find_section(&myst_elf.elf, ".mystenc", &buffer, &buffer_length) !=
        0)
    {
        fprintf(
            stderr, "Failed to extract enclave from %s\n", get_program_file());
        goto done;
    }

    if (myst_write_file(scratch_path, buffer, buffer_length) != 0)
    {
        fprintf(stderr, "Failed to write %s\n", scratch_path);
        goto done;
    }

    if (elf_find_section(
            &myst_elf.elf,
            ".mystconfig",
            (unsigned char**)&config_buffer,
            &config_size) != 0)
    {
        fprintf(
            stderr, "Failed to extract config from %s\n", get_program_file());
        goto done;
    }
    elf_loaded = 1;

    // Need to duplicate the config buffer or we will be corrupting the image
    // data
    config_parsed_data_t parsed_data = {0};

    if (parse_config_from_buffer(
            (char*)config_buffer, config_size, &parsed_data) != 0)
    {
        fprintf(stderr, "Failed to process configuration\n");
    }
    if ((parsed_data.allow_host_parameters == 0) && (argc > 1))
    {
        printf(
            "Command line arguments will be ignored due to configuration.\n");
    }
    if (parsed_data.application_path == NULL)
    {
        fprintf(
            stderr,
            "No target filename in configuration. This should be the fully "
            "qualified path to the executable within the "
            "%s directory, but should be relative to this directory\n",
            app_dir);
        goto done;
    }

    if ((details = create_region_details_from_package(
             &myst_elf, parsed_data.heap_pages)) == NULL)
    {
        fprintf(stderr, "Failed to extract all sections\n");
        goto done;
    }

    if (_is_null_rootfs(details->rootfs.buffer, details->rootfs.buffer_size))
    {
        char* env;

        if (!(env = getenv("MYST_ROOTFS_PATH")))
        {
            fprintf(stderr, "MYST_ROOTFS_PATH is undefined\n");
            goto done;
        }

        if (access(env, R_OK) != 0)
        {
            fprintf(stderr, "MYST_ROOTFS_PATH=%s not found\n", env);
            goto done;
        }

        if (myst_strlcpy(options.rootfs, env, sizeof(options.rootfs)) >=
            sizeof(options.rootfs))
        {
            fprintf(
                stderr,
                "MYST_ROOTFS_PATH is too long (> %zu)\n",
                sizeof(options.rootfs));
            goto done;
        }
    }

    // build argv with application name. If we are allowed command line args
    // then append them also
    int num_args = 1; // argv[0];

    if (parsed_data.allow_host_parameters)
    {
        num_args = argc;
    }

    exec_args = malloc((num_args + 1) * sizeof(char*));
    if (exec_args == NULL)
    {
        fprintf(stderr, "out of memory\n");
        goto done;
    }
    exec_args[0] = parsed_data.application_path;
    int args_iter = 1;
    while (args_iter != num_args)
    {
        exec_args[args_iter] = argv[args_iter];
        args_iter++;
    }
    exec_args[args_iter] = NULL;

    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            unpack_dir) >= PATH_MAX)
    {
        fprintf(
            stderr, "File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }

    ret = exec_launch_enclave(
        scratch_path, type, flags, exec_args, envp, &options, max_threads);
    if (ret != 0)
    {
        fprintf(stderr, "Enclave %s returned %d\n", scratch_path, ret);
        goto done;
    }

done:
    if (unpack_dir)
        remove_recursive(unpack_dir);

    if (elf_loaded)
        elf_image_free(&myst_elf);

    if (details)
        free_region_details();

    if (exec_args)
        free(exec_args);

    return ret;
}
