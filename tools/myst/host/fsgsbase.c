#define _GNU_SOURCE
#include <myst/getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

static int _called_sigill_handler;

static void _sigill_handler(int signum, siginfo_t* siginfo, void* ucontext)
{
    /* advance to next instruction (after WRFSBASE) */
    ((ucontext_t*)ucontext)->uc_mcontext.gregs[REG_RIP] += 5;

    _called_sigill_handler = 1;
}

int test_user_space_fsgsbase(void)
{
    void* save;
    struct sigaction act;
    struct sigaction oldact;

    /* save the oldact fsbase */
    __asm__ volatile("mov %%fs:0, %0" : "=r"(save));

    /* install SIGILL handler */
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = _sigill_handler;
    sigaction(SIGILL, &act, &oldact);

    /* attempt the WRFSBASE instruction (possibly raising SIGILL) */
    __asm__ volatile("wrfsbase %0" ::"r"(NULL));

    /* if WRFSBASE instruction worked, then restore the orignal fsbase value */
    if (!_called_sigill_handler)
        __asm__ volatile("wrfsbase %0" ::"r"(save));

    /* restore the original SIGILL handler */
    sigaction(SIGILL, &oldact, NULL);

    return _called_sigill_handler ? -1 : 0;
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

#define FSGSBASE_USAGE \
    "\n\
Usage: %s %s [options]\n\
\n\
Synopsis:\n\
    This command checks whether a user-mode program may execute the FSGSBASE\n\
    instructions (RDFSBASE, WRFSBASE, RDGSBASE, and WRGSBASE). If so, the\n\
    exit code is zero. If not, the exit code is one.\n\
\n\
Options:\n\
    -h, --help  Print this help message\n\
    --quiet     Do not write anything to standard output\n\
\n"

int fsgsbase_action(int argc, const char* argv[])
{
    bool help = false;
    bool quiet = false;

    /* get the --help option */
    if (_getopt(&argc, argv, "--help", NULL) == 0 ||
        _getopt(&argc, argv, "-h", NULL) == 0)
    {
        help = true;
    }

    if (help)
    {
        printf(FSGSBASE_USAGE, argv[0], argv[1]);
        exit(0);
    }

    /* get the --quiet option */
    if (_getopt(&argc, argv, "--quiet", NULL) == 0 ||
        _getopt(&argc, argv, "-q", NULL) == 0)
    {
        quiet = true;
    }

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s %s\n", argv[0], argv[1]);
        exit(1);
    }

    if (test_user_space_fsgsbase() == 0)
    {
        if (!quiet)
            printf("FSGSBASE instructions are supported\n");

        exit(0);
    }
    else
    {
        if (!quiet)
            printf("FSGSBASE instructions are not supported\n");

        exit(1);
    }

    return 0;
}
