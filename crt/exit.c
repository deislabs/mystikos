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
    myst_fork_info_t arg = MYST_FORK_INFO_INITIALIZER;

    if (syscall(SYS_myst_get_fork_info, &arg) == 0)
    {
        if (arg.is_parent_of_fork || arg.is_child_fork)
        {
            /* processes dealing with pseudo fork cannot cleanup safely.
             * A parent of a forked process cannot do cleanup either as a child
             * may have registered a cleanup function but all memory to do with
             * children are already unloaded so could cause a crash. As a result
             * the parent must wait for the children to shutdown as well as not
             * do crt cleanup. Children cannot because they are sharing the CRT
             * with the parent and the parent already has a lot of state set up
             * for them. If the child shuts down the crt the parent will crash
             * as well as any siblings.
             */

            /* Because we are not going to do CRT cleanup we do need to make
             * sure files are flushed before they completely shutdown. This
             * would normally happen in the CRT cleanup code. */
            fflush(NULL);

            if (arg.is_parent_of_fork)
            {
                if (syscall(SYS_myst_kill_wait_child_forks) != 0)
                {
                    // failed so safest option is fast exit
                    _Exit(code);
                }
            }
            _Exit(code);
        }

        /* We are not a child pseudo-forked child, nor the parent of one we
         * can do normal shutdown */
        do_crt_exit(code);
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
