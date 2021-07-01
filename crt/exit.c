#include <myst/syscallext.h>
#include <stdio.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

void do_crt_exit(int code);

/*
 * If we were cloned with CLONE_VM | CLONE_VFORK we are sharing the process
 * heap between the parent and the child forked process.
 * All global variables the CRT uses are shared between the two processes.
 * If either process shuts down through exit() the CRT will clean up the process
 * by deleting memory, deallocating locks and various other things. In exit() we
 * call into the kernel to determine if we are a parent of a fork or a child
 * fork process. If we are a child fork we skip the cleanup and let the parent
 * process do that. If we are the parent process of forks we will terminate all
 * child forks, wait for them to exit, then proceed to cleanup If we are neither
 * a child forked process or parent of one we cleanup as normal.
 * Note: The CRT version of exit() was made weak and this is the strong version
 * that overwrites the CRT version.
 */
void exit(int code)
{
    bool am_parent_of_fork = false;
    bool am_child_fork = false;
    myst_fork_mode_t fork_mode = myst_fork_none;

    if (syscall(
            SYS_myst_get_fork_info,
            &fork_mode,
            &am_parent_of_fork,
            &am_child_fork) == 0)
    {
        if (am_child_fork)
        {
            // we are child fork so let parent cleanup
            _Exit(code);
        }
        else if (am_parent_of_fork)
        {
            // we have active child forked processes
            if (syscall(SYS_myst_kill_wait_child_forks) == 0)
            {
                // child fork process now terminated.
                // cleanup CRT as normal
                do_crt_exit(code);
            }
            else
            {
                // failed so safest option is fast exit
                _Exit(code);
            }
        }
        else
        {
            // regular process with nothing to do with fork.
            // cleanup CRT as normal
            do_crt_exit(code);
        }
    }
    else
    {
        // failed so safest option is fast exit
        _Exit(code);
    }

    for (;;)
        ;
}

/*
 * Note: The CRT version of exit() was made weak and this is the strong version
 * that overwrites the CRT version.
 */
void _Exit(int ec)
{
    syscall(SYS_exit_group, ec);
    for (;;)
        syscall(SYS_exit, ec);
}
