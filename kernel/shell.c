#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <myst/chars.h>
#include <myst/debugmalloc.h>
#include <myst/fdtable.h>
#include <myst/id.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/syscall.h>

#if !defined(MYST_RELEASE)

#define COLOR_LIGHT_BLUE "\e[94m"
#define COLOR_LIGHT_GREEN "\e[92m"
#define COLOR_RESET "\e[0m"

__attribute__((__unused__)) static void _dump_args(size_t argc, char** argv)
{
    printf("argc=%zu\n", argc);

    for (size_t i = 0; i < argc; i++)
        printf("argv[%zu]=%s\n", i, argv[i]);
}

typedef struct help
{
    const char* cmd;
    const char* msg;
} help_t;

static help_t _help[] = {
    {"help", "print this message"},
    {"ls", "list directory contents"},
    {"cd", "change the current directory"},
    {"pwd", "print the current directory"},
    {"mem", "print memory statistics"},
    {"cont", "leave shell and ocntinue execution"},
    {"fds", "list open file descriptors"},
    {"id", "print the current UID and GID"},
    {"maxthreads", "list open file descriptors"},
    {"hostname", "print the hostname"},
    {"mcheck", "check heap memory"},
    {"mdump", "print out in-use heap block"},
};

static size_t _nhelp = sizeof(_help) / sizeof(_help[0]);

static void _help_command(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    for (size_t i = 0; i < _nhelp; i++)
        printf("%-10s - %s\n", _help[i].cmd, _help[i].msg);

    printf("\n");
}

static void _ls_command(int argc, char** argv)
{
    char dirname[PATH_MAX];
    DIR* dir;
    struct dirent* ent;

    if (argc > 2)
    {
        myst_eprintf("%s: too many arguments\n", argv[0]);
        return;
    }

    if (argc == 2)
    {
        myst_strlcpy(dirname, argv[1], sizeof(dirname));
    }
    else
    {
        memset(dirname, 'a', sizeof(dirname));
        if (myst_syscall_getcwd(dirname, sizeof(dirname)) < 0)
            myst_panic("getcwd() failed");
    }

    if (!(dir = opendir(dirname)))
    {
        myst_eprintf("%s: no such directory: %s\n", argv[0], dirname);
        return;
    }

    while ((ent = readdir(dir)))
    {
        const char* name = ent->d_name;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        if (ent->d_type == DT_DIR)
            printf(COLOR_LIGHT_BLUE);

        printf("%s" COLOR_RESET "\n", name);
    }

    printf("\n");
    closedir(dir);
}

static void _pwd_command(void)
{
    char cwd[PATH_MAX];

    if (myst_syscall_getcwd(cwd, sizeof(cwd)) < 0)
        myst_panic("getcwd() failed");

    printf("%s\n", cwd);
}

static void _cd_command(int argc, char** argv)
{
    const char* dirname = "/";

    if (argc > 2)
    {
        myst_eprintf("%s: too many arguments\n", argv[0]);
        return;
    }

    if (argc == 2)
        dirname = argv[1];

    if (myst_syscall_chdir(dirname) < 0)
    {
        myst_eprintf("%s: no such file or directory: %s\n", argv[0], dirname);
        return;
    }
}

static void _mem_command(int argc, char** argv)
{
    extern void dlmalloc_stats(void);
    const size_t mb = 1024 * 1024;
    size_t total_ram = 0;
    size_t free_ram = 0;
    size_t used_ram;
    size_t rootfs_size = __myst_kernel_args.rootfs_size;

    (void)argc;
    (void)argv;

    myst_get_total_ram(&total_ram);
    myst_get_free_ram(&free_ram);
    used_ram = total_ram - free_ram;
    dlmalloc_stats();
    printf("total mman       =%11zu (%zumb)\n", total_ram, total_ram / mb);
    printf("used mman        =%11zu (%zumb)\n", used_ram, used_ram / mb);
    printf("free mman        =%11zu (%zumb)\n", free_ram, free_ram / mb);
    printf("cpio size        =%11zu (%zumb)\n", rootfs_size, rootfs_size / mb);
    printf("\n");
}

void myst_shell(const char* msg)
{
    char** argv = NULL;

    if (msg)
    {
        printf(COLOR_LIGHT_GREEN "%s" COLOR_RESET "\n", msg);
    }

    for (;;)
    {
        char line[1024];
        long n;
        size_t argc;

        if ((n = myst_tcall_readline("myst$ ", line, sizeof(line))) < 0)
        {
            myst_eprintf("error: readline failed!\n");
            continue;
        }

        /* split the string into tokens */
        if (myst_strsplit(line, " \r\n\t", &argv, &argc) != 0)
            myst_panic("myst_strsplit() failed");

        if (argc == 0)
            continue;

        if (strcmp(argv[0], "help") == 0)
        {
            _help_command(argc, argv);
        }
        else if (strcmp(argv[0], "ls") == 0)
        {
            _ls_command(argc, argv);
        }
        else if (strcmp(argv[0], "pwd") == 0)
        {
            _pwd_command();
        }
        else if (strcmp(argv[0], "cd") == 0)
        {
            _cd_command(argc, argv);
        }
        else if (strcmp(argv[0], "mem") == 0)
        {
            _mem_command(argc, argv);
        }
        else if (strcmp(argv[0], "fds") == 0)
        {
            myst_fdtable_list(myst_fdtable_current());
        }
        else if (strcmp(argv[0], "maxthreads") == 0)
        {
            printf("%zu\n\n", __myst_kernel_args.max_threads);
        }
        else if (strcmp(argv[0], "id") == 0)
        {
            uid_t uid = MYST_DEFAULT_UID;
            uid_t gid = MYST_DEFAULT_GID;
            printf("uid=%d gid=%d\n", uid, gid);
            printf("\n");
        }
        else if (strcmp(argv[0], "hostname") == 0)
        {
            struct utsname buf;

            if (myst_syscall_uname(&buf) != 0)
            {
                myst_eprintf("%s: myst_syscall_uname() failed\n", argv[0]);
            }
            else
            {
                printf("%s\n\n", buf.nodename);
            }
        }
        else if (strcmp(argv[0], "mcheck") == 0)
        {
            myst_debug_malloc_check(false);
        }
        else if (strcmp(argv[0], "mdump") == 0)
        {
            myst_debug_malloc_dump();
        }
        else if (strcmp(argv[0], "cont") == 0)
        {
            break;
        }
        else
        {
            myst_eprintf("command not found: %s\n", argv[0]);
        }

        free(argv);
        argv = NULL;
    }

    if (argv)
        free(argv);
}

#endif /* !defined(MYST_RELEASE) */
