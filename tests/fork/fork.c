// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <errno.h>
#include <myst/assume.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int myst_fork(void);

static int _gettid(void)
{
    return syscall(SYS_gettid);
}
static int _getpid(void)
{
    return syscall(SYS_getpid);
}
static int _getppid(void)
{
    return syscall(SYS_getppid);
}
static int _getpgid(void)
{
    return syscall(SYS_getpgid);
}

int _printf(const char* fmt, ...)
{
    static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
    va_list ap;

    va_start(ap, fmt);
    pthread_mutex_lock(&_lock);
    fprintf(
        stderr,
        "pid=%d tid=%d ppid=%d gpid=%d: ",
        _getpid(),
        _gettid(),
        _getppid(),
        _getpgid());
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
    pthread_mutex_unlock(&_lock);
    va_end(ap);
}

int test_fork1(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child\n");
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork2(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. sleeping\n");
        sleep(1);
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        if (WIFSIGNALED(wstatus) != 0)
        {
            fprintf(stderr, "waitpid WIFSIGNALED was not sent a kill.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork3(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. sleeping and waiting for signal\n");
        sleep(1);
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Sending signal to shut down child\n");
        kill(pid, SIGKILL);
        _printf("Waiting for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "waitpid WIFSIGNALED should be set.\n");
            exit(1);
        }
        if (WTERMSIG(wstatus) != 9)
        {
            fprintf(
                stderr,
                "waitpid WTERMSIG should be 9 as child was killed via "
                "SIGKILL).\n");
            exit(1);
        }
        if (WIFSIGNALED(wstatus) == 0)
        {
            fprintf(
                stderr,
                "waitpid WIFSIGNALED should have told us child was killed.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

int test_fork4(int argc, const char* argv[])
{
    pid_t pid = fork();
    int variable = 0;

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. setting variable\n");
        variable = 1;
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("waiting for child to shut down\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        if (variable != 0)
        {
            fprintf(stderr, "Variable should not be changed.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
    }
    return 0;
}

/* fork: child fork calls exec */
int test_fork_exec1(int argc, const char* argv[])
{
    printf("*** Starting test_fork_exec1 ***\n");
    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. callingf execl\n");
        const char* path = "/bin/fork_child";
        if (execl(path, path, "just_return", NULL) != 0)
        {
            fprintf(stderr, "execl should not fail\n");
            exit(2);
        }
        fprintf(stderr, "execl should not return\n");
        exit(2);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(stderr, "waitpid on child pid did not return child pid.\n");
            exit(1);
        }
        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 10)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
        printf("*** Finished test_fork_exec1 ***\n");
    }
    return 0;
}

/* fork-wait: exit child fork without exec */
int test_fork_exec2(int argc, const char* argv[])
{
    printf("*** Starting test_fork_exec2 ***\n");

    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. sleeping\n");
        sleep(1);
        _printf("Shutting down child\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent... Child should have already gone as doing "
                "a fork-wait and we called exit\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(
                stderr,
                "waitpid - child should have exited even though it was "
                "sleeping.\n");
            exit(1);
        }

        if (!WIFEXITED(wstatus))
        {
            fprintf(stderr, "waitpid WIFEXITED should be set.\n");
            exit(1);
        }
        if (WEXITSTATUS(wstatus) != 1)
        {
            fprintf(
                stderr,
                "waitpid WEXITSTATUS should be 1 as child did exit(1).\n");
            exit(1);
        }
        if (WIFSIGNALED(wstatus) != 0)
        {
            fprintf(stderr, "waitpid WIFSIGNALED was not sent a kill.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
        printf("*** Finished test_fork_exec2 ***\n");
    }
    return 0;
}

/* fork-wait: child fork crashes */
int test_fork_exec3(int argc, const char* argv[])
{
    printf("*** Starting test_fork_exec3 ***\n");

    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. crashing\n");
        *((volatile unsigned char*)0) = 0;
        fprintf(stderr, "child should not get here\n");
        exit(1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent... Child should have already gone as doing "
                "a fork-wait and we crashed without calling exec\n");
        if (waitpid(pid, &wstatus, WNOHANG) != pid)
        {
            fprintf(
                stderr,
                "waitpid - child should have exited because it crashed.\n");
            exit(1);
        }

        if (!WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "waitpid WIFSIGNALED should be set.\n");
            exit(1);
        }
        if (WTERMSIG(wstatus) != SIGSEGV)
        {
            fprintf(
                stderr,
                "waitpid termination signal should be SIGSEGV, we got %d.\n",
                WTERMSIG(wstatus));
            exit(1);
        }
        _printf("Shutting down parent\n");
        printf("*** Finished test_fork_exec3 ***\n");
    }
    return 0;
}

int test_nofork1(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0)
    {
        if (errno == ENOTSUP)
        {
            _printf("Fork not supported as expected\n");
        }
        else
        {
            _printf(
                "%s: fork() failed with incorrect error: %d\n", argv[0], pid);
            exit(-1);
        }
    }
    else if (pid == 0)
    {
        _printf("*** inside child\n");
        _printf("fork should have fail\n");
        exit(-1);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent\n");
        _printf("Fork should have failed\n");
        _printf("Waiting for child to shutdown\n");
        waitpid(pid, &wstatus, 0);
        exit(-1);
    }
    return 0;
}

/* Test that after a fork/exec the sighandler is reset */
static _Atomic(int) clear_sig_usr1 = 0;

void test_clear_sig_handler(int signo)
{
    switch (signo)
    {
        case SIGUSR1:
            clear_sig_usr1 = 1;
            break;
        default:
            exit(20);
    }
}

int test_forkexec_sighandler(int argc, const char* argv[])
{
    printf("*** Starting test_forkexec_sighandler ***\n");

    if (signal(SIGUSR1, test_clear_sig_handler) == SIG_ERR)
    {
        fprintf(stderr, "failed to set sighandler on child.\n");
        exit(1);
    }

    pid_t pid = fork();

    if (pid < 0)
    {
        fprintf(stderr, "%s: fork() failed: %d\n", argv[0], pid);
        exit(3);
    }
    else if (pid == 0)
    {
        _printf("*** inside child.. calling execl\n");
        const char* path = "/bin/fork_child";
        if (execl(path, path, "kill_usr1", NULL) != 0)
        {
            fprintf(stderr, "execl should not fail\n");
            exit(2);
        }
        fprintf(stderr, "execl should not return\n");
        exit(2);
    }
    else
    {
        int wstatus;
        _printf("*** inside parent... wait for child to shutdown\n");
        if (waitpid(pid, &wstatus, 0) != pid)
        {
            fprintf(
                stderr,
                "waitpid - child should have exited because it crashed.\n");
            exit(1);
        }

        /* Child should get a SIGUSR1 unless theexec  child inherited the
         * sighandlers */
        if (!WIFSIGNALED(wstatus))
        {
            fprintf(stderr, "waitpid WIFSIGNALED should be set.\n");
            exit(1);
        }
        if (WTERMSIG(wstatus) != SIGUSR1)
        {
            fprintf(
                stderr,
                "waitpid termination signal should be SIGUSR1, we got %d.\n",
                WTERMSIG(wstatus));
            exit(1);
        }
        if (clear_sig_usr1 != 0)
        {
            fprintf(
                stderr, "there should be no calls on the signal handler.\n");
            exit(1);
        }
        _printf("Shutting down parent\n");
        printf("*** Finished test_forkexec_sighandler ***\n");
    }
    return 0;
}

static long g_child1_pid = 0;
static long g_child2_pid = 0;

int test_fork_orphaned(int argc, const char* argv[])
{
    long pid1 = 0;
    long pid2 = 0;

    printf("*** Starting test_fork_orphaned ***\n");

    pid1 = fork();
    if (pid1 == 0)
    {
        _printf("child 1 started\n");
        pid2 = fork();
        if (pid2 == 0)
        {
            // Wait until we get a signal
            _printf("child 2 started, going to sleep\n");
            pause();
        }
        else if (pid2 > 0)
        {
            g_child2_pid = pid2;

            // level 1 child
            long ret;
            while (1)
            {
                _printf("child 1 waiting for child 2 to start\n");
                // Loop until the child starts up
                ret = waitpid(pid2, NULL, WNOHANG);
                if (ret == 0)
                {
                    // child
                    // We can now exit and the second level child should
                    // continue to run
                    _printf("child 2 started, shutting down child 1\n");
                    exit(pid1);
                }
                else if (ret == ECHILD)
                {
                    // not started yet
                    // We need to wait
                    _printf("Child 1 did not find child 2 yet, sleeping\n");
                    struct timespec sleeptime = {.tv_sec = 0,
                                                 .tv_nsec = 1000000};
                    nanosleep(&sleeptime, NULL);
                }
                else if (ret == pid2)
                {
                    // child shutdown when it should not
                    // ERROR
                    _printf("child 1 waited for child 2 and it shutdown by "
                            "error\n");
                    exit(-1);
                }
                else
                {
                    // Some other error
                    // ERROR
                    _printf("child 1 waited for child 1 and got an error\n");
                    exit(-2);
                }
            }
        }
        else
        {
            // ERROR
            _printf("child 1 forking child 2 got an error\n");
            exit(-3);
        }
    }
    else if (pid1 > 0)
    {
        g_child1_pid = pid1;
        // parent
        while (1)
        {
            _printf("parent created child 1, waiting for child 1 to quit\n");
            long ret = waitpid(pid1, NULL, 0);
            if (ret == pid1)
            {
                _printf("child 1 shutdown as expected, checking child 2 is "
                        "still there\n");
                // child 1 has shut down
                ret = waitpid(g_child2_pid, NULL, WNOHANG);
                if (ret == 0)
                {
                    _printf("parent found child 2 still running, sending a "
                            "signal to shut it down\n");
                    // It is still running so send a signal to shut it down
                    kill(g_child2_pid, SIGALRM);

                    // wait for it to exit
                    _printf("parent waiting for child 2 to shutdown after "
                            "signal\n");
                    ret = waitpid(g_child2_pid, NULL, 0);
                    if (ret == g_child2_pid)
                    {
                        // yay! it worked as expected
                        _printf("parent acknowledges child 2 is done. We are "
                                "dont.\n");
                        printf("*** Finished test_fork_orphaned ***\n");
                        exit(0);
                    }
                    else
                    {
                        // child process did not shut down or some other error
                        // happened
                        _printf("parent waiting for child 2 got unexpected "
                                "error\n");
                        exit(-4);
                    }
                }
                else
                {
                    _printf("parent got error checking that child 2 is "
                            "present. error or shutdown already\n");
                    // child 1 already gone so this means it shutdown already or
                    // something failed.
                    exit(-5);
                }
            }
            else if (ret == ECHILD)
            {
                _printf("parent didnt find child 1 yet, sleeping...\n");
                // child 1 has not started yet so sleep a bit
                struct timespec sleeptime = {.tv_sec = 0, .tv_nsec = 1000000};
                nanosleep(&sleeptime, NULL);
            }
            else
            {
                _printf(
                    "parent got an error waiting for child 1 to shutdown\n");
                exit(-6);
            }
        }
    }
    else
    {
        // fork failed
        _printf("parent failed to start child 1\n");
        exit(-7);
    }

    _printf("*** FINISHED UNEXPECTEDLY test_fork_orphaned ***\n");
    return -8;
}
int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Not enough args... which test?\n");
        return -1;
    }
    if (strcmp(argv[1], "fork") == 0)
    {
        myst_assume(test_fork1(argc, argv) == 0);
        myst_assume(test_fork2(argc, argv) == 0);
        myst_assume(test_fork3(argc, argv) == 0);
        myst_assume(test_fork4(argc, argv) == 0);
        myst_assume(test_fork_exec1(argc, argv) == 0);
    }
    else if (strcmp(argv[1], "forkwait") == 0)
    {
        myst_assume(test_fork_exec1(argc, argv) == 0);
        myst_assume(test_fork_exec2(argc, argv) == 0);
        myst_assume(test_fork_exec3(argc, argv) == 0);
    }
    else if (strcmp(argv[1], "nofork") == 0)
    {
        myst_assume(test_nofork1(argc, argv) == 0);
    }
    else if (strcmp(argv[1], "forkwait_sighandler") == 0)
    {
        myst_assume(test_forkexec_sighandler(argc, argv) == 0);
    }
    else if (strcmp(argv[1], "fork-orphaned") == 0)
    {
        myst_assume(test_fork_orphaned(argc, argv) == 0);
    }
    else
    {
        fprintf(stderr, "invalid argument\n");
        return -1;
    }
    return 0;
}
