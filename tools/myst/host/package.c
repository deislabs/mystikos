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

#include <myst/args.h>
#include <myst/elf.h>
#include <myst/getopt.h>
#include <myst/strings.h>
#include <openenclave/host.h>

#include "../config.h"
#include "cpio.h"
#include "exec.h"
#include "myst/file.h"
#include "myst_args.h"
#include "process.h"
#include "pubkeys.h"
#include "regions.h"
#include "roothash.h"
#include "sections.h"
#include "sign.h"
#include "strace.h"
#include "utils.h"

_Static_assert(PAGE_SIZE == 4096, "");

#define ERR_NOEXIT(...)       \
    _err_noexit(__VA_ARGS__); \
    ret = -1

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
    --help                  -- this message\n\
    --pubkey=pem_file       -- trust disks signed by this key (repeatable)\n\
    --roothash=ascii_file   -- trust disks with this roothash (repeatable)\n\
    --outfile=file, -o=file -- place output in this file\n\
\n\
    Bring your own signing engine options:\n\
    --signing-engine-name\n\
    --signing-engine-path\n\
    --signing-engine-key\n\
    All three parameters must be passed if using a signing engine.\n\
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
        ERR_NOEXIT("Failed to load %s", path);
        goto done;
    }
    if (elf_add_section(elf, section_name, SHT_PROGBITS, image, image_length) !=
        0)
    {
        ERR_NOEXIT("Failed to add %s to elf image", path);
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
    char pubkeys_file[PATH_MAX];
    char roothashes_file[PATH_MAX];
    char scratch_path[PATH_MAX];
    char scratch_path2[PATH_MAX];
    config_parsed_data_t parsed_data = {0};
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    const char* signing_engine_key = NULL;
    const char* signing_engine_name = NULL;
    const char* signing_engine_path = NULL;
    myst_buf_t roothash_buf = MYST_BUF_INITIALIZER;
    bool using_ext2 = false;
    const char* outfile = NULL;
    char err[128];

    /* Get --pubkey=filename options */
    get_pubkeys_options(&argc, argv, pubkeys, max_pubkeys, &num_pubkeys);

    /* Get --roothash=filename options */
    get_roothash_options(&argc, argv, &roothash_buf);

    if ((argc < 4) || (cli_getopt(&argc, argv, "--help", NULL) == 0) ||
        (cli_getopt(&argc, argv, "-h", NULL) == 0))
    {
        ERR_NOEXIT(USAGE_PACKAGE, argv[0], argv[0]);
        goto done;
    }

    /* Get the --outfile=file option */
    if (myst_getopt(&argc, argv, "--outfile", &outfile, err, sizeof(err)) < 0)
    {
        _err("%s: %s\n", argv[0], err);
    }

    /* Get the -o=file option (the short-form of --outfile) */
    if (!outfile &&
        myst_getopt(&argc, argv, "-o", &outfile, err, sizeof(err)) < 0)
    {
        _err("%s: %s\n", argv[0], err);
    }

    cli_getopt(&argc, argv, "--signing-engine-name", &signing_engine_name);
    cli_getopt(&argc, argv, "--signing-engine-path", &signing_engine_path);
    cli_getopt(&argc, argv, "--signing-engine-key", &signing_engine_key);
    if ((signing_engine_key || signing_engine_name || signing_engine_path) &&
        (!signing_engine_key || !signing_engine_name || !signing_engine_path))
    {
        _err_noexit(
            "If using a signing engine all three parameters are required: "
            "--signing-engine-key, "
            "--signing-engine-name and --signing-engine-path\n");
        _err(USAGE_PACKAGE, argv[0], argv[0]);
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

    create_pubkeys_file(pubkeys, num_pubkeys, pubkeys_file);

    if (create_roothashes_file(&roothash_buf, roothashes_file) != 0)
        _err("failed to create roothashes file");

    /* ATTN:MEB: create roothashes file here! */

    tmp_dir = mkdtemp(dir_template);
    if (tmp_dir == NULL)
    {
        ERR_NOEXIT("Failed to create temporary directory in /tmp\n");
        goto done;
    }

    if (snprintf(rootfs_file, PATH_MAX, "%s/rootfs.pkg", tmp_dir) >= PATH_MAX)
    {
        ERR_NOEXIT("File path too long? %s/rootfs.pkg\n", tmp_dir);
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
            ERR_NOEXIT(
                "Failed to create root filesystem \"%s\" from directory "
                "\"%s\"\n",
                rootfs_file,
                app_dir);
            goto done;
        }
    }
    else
    {
        // generate a dummy CPIO rootfs with zero-filled page. This indicates
        // that the rootfs is not a CPIO archive and that the kernel should
        // attempt to load an EXT2 instead.
        int fd;
        uint8_t page[PAGE_SIZE];
        const int flags = O_CREAT | O_WRONLY | O_TRUNC;

        if ((fd = open(rootfs_file, flags, 0640)) < 0)
            _err("failed to create temporary file");

        memset(page, 0, sizeof(page));

        if (write(fd, page, sizeof(page)) != sizeof(page))
            _err("failed to create file: %s", rootfs_file);

        close(fd);

        using_ext2 = true;
    }

    assert(myst_validate_file_path(config_file));
    if (parse_config_from_file(config_file, &parsed_data) != 0)
    {
        ERR_NOEXIT(
            "Failed to generate OE configuration file %s from Mystikos "
            "configuration file %s\n",
            scratch_path2,
            config_file);
        goto done;
    }

    if (using_ext2)
    {
        /* Fail if application image would be unable to load an EXT2 image */
        if (!(parsed_data.oe_debug || roothash_buf.size || num_pubkeys))
        {
            _err("When using EXT2, one of the following is required: \n"
                 "    (1) Debug=1 option in the config file (non-secure)\n"
                 "    (2) --roothash=<filename> option (secure)\n"
                 "    (3) --pubkey=<pemfile> option (secure)\n"
                 "    (4) signature struct at end of EXT2 image (secure)\n");
        }
    }

    target = parsed_data.application_path;
    if ((target == NULL) || (target[0] != '/'))
    {
        ERR_NOEXIT(
            "target in config file must be fully qualified path within rootfs");
        goto done;
    }

    appname = strrchr(target, '/');
    if (appname == NULL)
    {
        ERR_NOEXIT("Failed to get appname from target path");
        goto done;
    }
    appname++;
    if (*appname == '\0')
    {
        ERR_NOEXIT("Failed to get appname from target path");
        goto done;
    }

    // sign the enclave and measure all regions of enclave
    if (signing_engine_path)
    {
        // optional path option for signing engine
        const char* sign_engine_args[] = {argv[0],
                                          "sign",
                                          rootfs_file,
                                          pem_file,
                                          config_file,
                                          "--pubkeys",
                                          pubkeys_file,
                                          "--roothashes",
                                          roothashes_file,
                                          "--outdir",
                                          tmp_dir,
                                          "--signing-engine-name",
                                          signing_engine_name,
                                          "--signing-engine-key",
                                          signing_engine_key,
                                          "--signing-engine-path",
                                          signing_engine_path};
        // Sign and copy everything into app.signed directory
        if (_sign(
                sizeof(sign_engine_args) / sizeof(sign_engine_args[0]),
                sign_engine_args) != 0)
        {
            ERR_NOEXIT("Failed to sign enclave file");
            goto done;
        }
    }
    else if (signing_engine_name)
    {
        // none engine optional path, but still signing engine
        const char* sign_engine_args[] = {argv[0],
                                          "sign",
                                          rootfs_file,
                                          pem_file,
                                          config_file,
                                          "--pubkeys",
                                          pubkeys_file,
                                          "--roothashes",
                                          roothashes_file,
                                          "--outdir",
                                          tmp_dir,
                                          "--signing-engine-name",
                                          signing_engine_name,
                                          "--signing-engine-key",
                                          signing_engine_key};
        // Sign and copy everything into app.signed directory
        if (_sign(
                sizeof(sign_engine_args) / sizeof(sign_engine_args[0]),
                sign_engine_args) != 0)
        {
            ERR_NOEXIT("Failed to sign enclave file");
            goto done;
        }
    }
    else
    {
        // none engine option
        const char* sign_args[] = {argv[0],
                                   "sign",
                                   rootfs_file,
                                   pem_file,
                                   config_file,
                                   "--pubkeys",
                                   pubkeys_file,
                                   "--roothashes",
                                   roothashes_file,
                                   "--outdir",
                                   tmp_dir};

        // Sign and copy everything into app.signed directory
        if (_sign(sizeof(sign_args) / sizeof(sign_args[0]), sign_args) != 0)
        {
            ERR_NOEXIT("Failed to sign enclave file");
            goto done;
        }
    }

    // Now package everything up in a single binary
    elf_t elf;

    memset(&elf, 0, sizeof(elf));

    // First load the myst application so we can add the other components
    // as named sections in the image
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/myst", tmp_dir) >= PATH_MAX)
    {
        ERR_NOEXIT("File path too long: %s/bin/myst", tmp_dir);
        goto done;
    }
    if (elf_load(scratch_path, &elf) != 0)
    {
        ERR_NOEXIT("Failed to load %s/bin/myst", tmp_dir);
        goto done;
    }

    // Add the enclave to myst
    if (snprintf(
            scratch_path, PATH_MAX, "%s/lib/openenclave/mystenc.so", tmp_dir) >=
        PATH_MAX)
    {
        ERR_NOEXIT(
            "File path too long: %s/openenclave/lib/mystenc.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".mystenc") != 0)
    {
        ERR_NOEXIT(
            "Failed to add %s to enclave section .mystenc", scratch_path);
        goto done;
    }

    // Add the enclave CRT to myst
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystcrt.so", tmp_dir) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path too long: %s/lib/libmystcrt.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libmystcrt") != 0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .libmystscrt",
            scratch_path);
        goto done;
    }

    // Add the kernel to myst
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/libmystkernel.so", tmp_dir) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path too long: %s/lib/libmystkernel.so", tmp_dir);
        goto done;
    }
    if (_add_image_to_elf_section(&elf, scratch_path, ".libmystkernel") != 0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .libmystkernel",
            scratch_path);
        goto done;
    }

    // Add the rootfs to myst
    if (_add_image_to_elf_section(&elf, rootfs_file, ".mystrootfs") != 0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .mystrootfs",
            rootfs_file);
        goto done;
    }

    // Add the pubkeys to myst
    if (_add_image_to_elf_section(&elf, pubkeys_file, ".mystpubkeys") != 0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .mystpubkeys",
            pubkeys_file);
        goto done;
    }

    // Add the roothashes to myst
    if (_add_image_to_elf_section(&elf, roothashes_file, ".mystroothashes") !=
        0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .mystroothashes",
            roothashes_file);
        goto done;
    }

    // Add the config to myst
    assert(myst_validate_file_path(config_file));
    if (_add_image_to_elf_section(&elf, config_file, ".mystconfig") != 0)
    {
        ERR_NOEXIT(
            "Failed to add image %s to enclave section .mystconfig",
            config_file);
        goto done;
    }

    // Save new elf image back
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path too long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }
    int fd = open(scratch_path, O_WRONLY | O_CREAT | O_TRUNC, 0774);
    if (fd == 0)
    {
        ERR_NOEXIT(
            "Failed to epn file to write final binary image back to %s",
            scratch_path);
        goto done;
    }
    if (myst_write_file_fd(fd, elf.data, elf.size) != 0)
    {
        close(fd);
        ERR_NOEXIT("File to save final binary image back to: %s", scratch_path);
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
        ERR_NOEXIT("Failed to make destination directory myst\n");
        goto done;
    }
    if ((mkdir("myst/bin", 0775) != 0) && (errno != EEXIST))
    {
        ERR_NOEXIT("Failed to make destination directory myst/bin\n");
        goto done;
    }

    // Destination filename
    if (snprintf(scratch_path, PATH_MAX, "myst/bin/%s", appname) >= PATH_MAX)
    {
        ERR_NOEXIT("File path too long: myst/bin/%s", appname);
        goto done;
    }

    // Source filename
    if (snprintf(scratch_path2, PATH_MAX, "%s/bin/%s", tmp_dir, appname) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path too long: %s/bin/%s", tmp_dir, appname);
        goto done;
    }

    if (!outfile)
        outfile = scratch_path;

    if (myst_copy_file(scratch_path2, outfile) != 0)
    {
        ERR_NOEXIT(
            "Failed to copy final package from %s to %s",
            scratch_path2,
            outfile);
        goto done;
    }

    /* Tell the console user that the packaged program has been created */
    printf("Created %s\n\n", outfile);

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
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG_AUTO;
    struct myst_options options = {0};
    char unpack_dir_template[] = "/tmp/mystXXXXXX";
    char* unpack_dir = NULL;
    int ret = -1;
    const char** exec_args = NULL;
    myst_args_t mount_mappings = {0};
    sections_t sections = {0};

    /* Get options */
    {
        // process ID mapping options
        cli_get_mapping_opts(&argc, argv, &options.host_enc_uid_gid_mappings);

        // retrieve mount mapping options
        cli_get_mount_mapping_opts(&argc, argv, &mount_mappings);

        /* Get --trace-syscalls option */
        if (cli_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            cli_getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.strace_config.trace_syscalls = true;
        }

        if (myst_strace_parse_config(&argc, argv, &options.strace_config) == 0)
        {
            options.strace_config.trace_syscalls = true;
        }
    }

    /* Get --trace option */
    if (cli_getopt(&argc, argv, "--trace-errors", NULL) == 0 ||
        cli_getopt(&argc, argv, "--etrace", NULL) == 0)
    {
        options.trace_errors = true;
    }

    /* Get --trace-times option */
    if (cli_getopt(&argc, argv, "--trace-times", NULL) == 0 ||
        cli_getopt(&argc, argv, "--ttrace", NULL) == 0)
    {
        options.trace_times = true;
    }

    /* Get --memcheck option */
    if (cli_getopt(&argc, argv, "--memcheck", NULL) == 0)
        options.memcheck = true;

    /* Check --nobrk option */
    if (cli_getopt(&argc, argv, "--nobrk", NULL) == 0)
    {
        ERR_NOEXIT("--nobrk not allowed for packaged applications."
                   " Can be enabled by setting NoBrk=true in config.json\n");
        goto done;
    }

    /* Check --exec-stack option */
    if (cli_getopt(&argc, argv, "--exec-stack", NULL) == 0)
    {
        ERR_NOEXIT("--exec-stack not allowed for packaged applications."
                   " Can be enabled by setting ExecStack=true in "
                   "config.json\n");
        goto done;
    }

    /* Check --host-uds option */
    if (cli_getopt(&argc, argv, "--host-uds", NULL) == 0)
    {
        ERR_NOEXIT("--host-uds not allowed for packaged applications."
                   " Can be enabled by setting HostUDS=true in "
                   "config.json\n");
        goto done;
    }

    /* Get --perf option */
    if (cli_getopt(&argc, argv, "--perf", NULL) == 0)
        options.perf = true;

    /* Get --report-native-tids option */
    if (cli_getopt(&argc, argv, "--report-native-tids", NULL) == 0)
        options.report_native_tids = true;

    /* Get --max-affinity-cpus */
    {
        const char* arg = NULL;

        if ((cli_getopt(&argc, argv, "--max-affinity-cpus", &arg) == 0))
        {
            char* end = NULL;
            size_t val = strtoull(arg, &end, 10);

            if (!end || *end != '\0')
            {
                ERR_NOEXIT(
                    "%s: bad --max-affinity-cpus=%s option\n", argv[0], arg);
                goto done;
            }

            options.max_affinity_cpus = val;
        }
    }

    /* Get --rootfs=<path> option if any  */
    {
        const char* arg = NULL;

        if ((cli_getopt(&argc, argv, "--rootfs", &arg) == 0))
        {
            if (access(arg, R_OK) != 0)
            {
                ERR_NOEXIT("%s: bad --rootfs option: %s", argv[0], arg);
                goto done;
            }

            if (MYST_STRLCPY(options.rootfs, arg) >= sizeof(options.rootfs))
            {
                ERR_NOEXIT(
                    "--rootfs option is too long (> %zu)\n",
                    sizeof(options.rootfs));
                goto done;
            }
        }
    }

    /* determine whether debug symbols are needed */
    {
        int r;

        if ((r = process_is_being_traced()) < 0)
            _err("process_is_being_traced() failed: %d", r);

        options.debug_symbols = (bool)r;
    }

    if (!realpath(argv[0], full_app_path))
    {
        ERR_NOEXIT("Invalid path %s\n", argv[0]);
        goto done;
    }

    app_dir = full_app_path;

    if (!(app_name = strrchr(full_app_path, '/')))
    {
        ERR_NOEXIT("Invalid path (missing slash): %s\n", full_app_path);
        goto done;
    }

    *app_name = '\0';
    app_name++;

    // Create a directory to unpack the package into, and to run from,
    // as well as the directory structure we need
    if ((unpack_dir = mkdtemp(unpack_dir_template)) == NULL)
    {
        ERR_NOEXIT("Failed to create unpack directory\n");
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib", unpack_dir) >= PATH_MAX)
    {
        ERR_NOEXIT("File path %s/lib is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        ERR_NOEXIT("Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/bin", unpack_dir) >= PATH_MAX)
    {
        ERR_NOEXIT("File path %s/bin is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        ERR_NOEXIT("Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }
    if (snprintf(scratch_path, PATH_MAX, "%s/lib/openenclave", unpack_dir) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path %s/lib/openenclave is too long\n", unpack_dir);
        goto done;
    }
    if ((mkdir(scratch_path, DIR_MODE) != 0) && (errno != EEXIST))
    {
        ERR_NOEXIT("Failed to create directory \"%s\".\n", scratch_path);
        goto done;
    }

    // Load main executable so we can extract sections
    if (load_sections(get_program_file(), &sections) != 0)
    {
        ERR_NOEXIT("failed to load myst image: %s\n", get_program_file());
        goto done;
    }

    // copy executable to unpack directory where we will run it from
    if (snprintf(scratch_path, PATH_MAX, "%s/bin/%s", unpack_dir, app_name) >=
        PATH_MAX)
    {
        ERR_NOEXIT("File path %s/bin/%s is too long\n", unpack_dir, app_name);
        goto done;
    }
    if (myst_copy_file(get_program_file(), scratch_path) < 0)
    {
        ERR_NOEXIT(
            "Failed to copy %s to %s\n", get_program_file(), scratch_path);
        goto done;
    }

    // Make enclave directory and extract enclave into it
    if (snprintf(
            scratch_path,
            PATH_MAX,
            "%s/lib/openenclave/mystenc.so",
            unpack_dir) >= PATH_MAX)
    {
        ERR_NOEXIT("File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }

    if (myst_write_file(
            scratch_path, sections.mystenc_data, sections.mystenc_size) != 0)
    {
        ERR_NOEXIT("Failed to write %s\n", scratch_path);
        goto done;
    }

    // Need to duplicate the config buffer or we will be corrupting the image
    // data
    config_parsed_data_t parsed_data = {0};

    if (parse_config_from_buffer(
            (char*)sections.mystconfig_data,
            sections.mystconfig_size,
            &parsed_data) != 0)
    {
        ERR_NOEXIT("Failed to process configuration\n");
    }
    if ((parsed_data.allow_host_parameters == 0) && (argc > 1))
    {
        printf(
            "Command line arguments will be ignored due to configuration.\n");
    }
    if (parsed_data.application_path == NULL)
    {
        ERR_NOEXIT(
            "No target filename in configuration. This should be the fully "
            "qualified path to the executable within the "
            "%s directory, but should be relative to this directory\n",
            app_dir);
        goto done;
    }

    /*
       Enable nobrk option only when config.json sets NoBrk=true.
       Else, default to false.
    */
    options.nobrk = parsed_data.no_brk;
    options.exec_stack = parsed_data.exec_stack;
    options.host_uds = parsed_data.host_uds;

    if ((details = create_region_details_from_package(
             &sections, parsed_data.heap_pages)) == NULL)
    {
        ERR_NOEXIT("Failed to extract all sections\n");
        goto done;
    }

    if (_is_null_rootfs(details->rootfs.buffer, details->rootfs.buffer_size))
    {
        /* if rootfs has not already been specified by --rootfs=<path> */
        if (*options.rootfs == '\0')
        {
            char* env;

            if (!(env = getenv("MYST_ROOTFS_PATH")))
            {
                ERR_NOEXIT("MYST_ROOTFS_PATH is undefined\n");
                goto done;
            }

            if (access(env, R_OK) != 0)
            {
                ERR_NOEXIT("MYST_ROOTFS_PATH=%s not found\n", env);
                goto done;
            }

            if (MYST_STRLCPY(options.rootfs, env) >= sizeof(options.rootfs))
            {
                ERR_NOEXIT(
                    "MYST_ROOTFS_PATH is too long (> %zu)\n",
                    sizeof(options.rootfs));
                goto done;
            }
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
        ERR_NOEXIT("out of memory\n");
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
        ERR_NOEXIT("File path %s/lib/openenclave/ is too long\n", unpack_dir);
        goto done;
    }

    ret = exec_launch_enclave(
        scratch_path, type, flags, exec_args, envp, &mount_mappings, &options);
    if (ret != 0)
    {
        _err_noexit("Enclave %s returned %d\n", scratch_path, ret);
        goto done;
    }

done:
    myst_args_release(&mount_mappings);

    if (unpack_dir)
        remove_recursive(unpack_dir);

    free_sections(&sections);

    if (details)
        free_region_details();

    if (exec_args)
        free(exec_args);

    return ret;
}
