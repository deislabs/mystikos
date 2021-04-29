#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <myst/fdtable.h>
#include <myst/id.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>

#if !defined(MYST_RELEASE)

#define COLOR_LIGHT_BLUE "\e[94m"
#define COLOR_LIGHT_GREEN "\e[92m"
#define COLOR_RESET "\e[0m"

static long _readline(const char* prompt, char* buf, size_t count)
{
    size_t n = 0;

    if (!prompt || !buf || count == 0)
        return -EINVAL;

    *buf = '\0';

    write(STDOUT_FILENO, prompt, strlen(prompt) + 1);

    while (n + 1 < count)
    {
        char c = '\0';

        if (read(STDIN_FILENO, &c, 1) < 0)
            return -EIO;

        if (c == '\n')
            break;

        buf[n++] = c;
        buf[n] = '\0';
    }

    return n;
}

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
    {"maxthreads", "print the maximum number of threads"},
    {"numthreads", "print the number of threads"},
    {"hostname", "print the hostname"},
    {"mcheck", "check heap memory"},
    {"mdump", "print in-use malloc'd blocks"},
    {"mused", "print amount of malloc'd memory"},
    {"args", "print the command line arguments"},
    {"env", "print the environment variables"},
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
    DIR* dir;
    struct dirent* ent;
    struct vars
    {
        char dirname[PATH_MAX];
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        myst_panic("out of memory");

    if (argc > 2)
    {
        myst_eprintf("%s: too many arguments\n", argv[0]);
        return;
    }

    if (argc == 2)
    {
        myst_strlcpy(v->dirname, argv[1], sizeof(v->dirname));
    }
    else
    {
        memset(v->dirname, 'a', sizeof(v->dirname));
        if (myst_syscall_getcwd(v->dirname, sizeof(v->dirname)) < 0)
            myst_panic("getcwd() failed");
    }

    if (!(dir = opendir(v->dirname)))
    {
        myst_eprintf("%s: no such directory: %s\n", argv[0], v->dirname);
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

    if (v)
        free(v);
}

static void _pwd_command(void)
{
    struct vars
    {
        char cwd[PATH_MAX];
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        myst_panic("out of memory");

    if (myst_syscall_getcwd(v->cwd, sizeof(v->cwd)) < 0)
        myst_panic("getcwd() failed");

    printf("%s\n", v->cwd);

    if (v)
        free(v);
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
    size_t n;
    struct vars
    {
        myst_mman_stats_t buf;
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        myst_panic("out of memory");

    myst_mman_stats(&v->buf);

    (void)argc;
    (void)argv;

    n = v->buf.total_size;
    printf("total ram    =%11zu (%zumb)\n", n, n / mb);

    n = v->buf.free_size;
    printf("free ram     =%11zu (%zumb)\n", n, n / mb);

    n = v->buf.used_size;
    printf("used ram     =%11zu (%zumb)\n", n, n / mb);

    n = v->buf.map_size;
    printf("map used     =%11zu (%zumb)\n", n, n / mb);

    n = v->buf.brk_size;
    printf("brk used     =%11zu (%zumb)\n", n, n / mb);

    n = __myst_kernel_args.rootfs_size;
    printf("cpio size    =%11zu (%zumb)\n", n, n / mb);

    n = __myst_kernel_args.kernel_size;
    printf("kernel size  =%11zu (%zumb)\n", n, n / mb);

    n = __myst_kernel_args.crt_size;
    printf("crt size     =%11zu (%zumb)\n", n, n / mb);

    n = __myst_kernel_args.archive_size;
    printf("archive size =%11zu (%zumb)\n", n, n / mb);

    printf("\n");

    if (v)
        free(v);
}

static void _env_command(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    for (size_t i = 0; i < __myst_kernel_args.envc; i++)
    {
        printf("%s\n", __myst_kernel_args.envp[i]);
    }

    printf("\n");
}

static void _args_command(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    for (size_t i = 0; i < __myst_kernel_args.argc; i++)
    {
        printf("%s\n", __myst_kernel_args.argv[i]);
    }

    printf("\n");
}

void myst_start_shell(const char* msg)
{
    char** argv = NULL;
    struct vars
    {
        char line[1024];
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        myst_panic("out of memory");

    if (msg)
    {
        printf(COLOR_LIGHT_GREEN "%s" COLOR_RESET "\n", msg);
    }

    for (;;)
    {
        long n;
        size_t argc;

        if ((n = _readline("myst$ ", v->line, sizeof(v->line))) < 0)
        {
            myst_eprintf("error: readline failed: %ld!\n", n);
            myst_panic("readline failed\n");
            continue;
        }

        /* split the string into tokens */
        if (myst_strsplit(v->line, " \r\n\t", &argv, &argc) != 0)
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
        else if (strcmp(argv[0], "numthreads") == 0)
        {
            printf("%zu\n\n", myst_get_num_threads());
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
        else if (strcmp(argv[0], "env") == 0)
        {
            _env_command(argc, argv);
        }
        else if (strcmp(argv[0], "args") == 0)
        {
            _args_command(argc, argv);
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

    if (v)
        free(v);
}

#endif /* !defined(MYST_RELEASE) */
