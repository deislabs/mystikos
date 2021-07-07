# Experimental feature: Pseudo fork in Mystikos

This is an experimental feature. By default it is disabled.

This document explains the implementation of fork with Mystikos and talks about the types of scenarios that could break as a result.
This is by no means a complete list of the types of issues that may happen, more the types of issues that have been encountered so far.
Although there are a number scenarios where this implementation will not work, there are a number of scenarios that will.

## Design

A typical kernel implements the process clone by creating a new address space that mimics that of the original, including the virtual address space states.

Mystikos implements fork via a newly cloned process by sharing the the calling processes address space.
Think of this as an extension of vfork.

With vfork (not currently implemented) you get a new process but you share the process address space and the same stack.
Our fork does give the forked process its own stack and we copy the contents of the calling process' stack into this, as well as fix up the frame pointers on the new stack so the stack unwind will work.
The kernel will duplicate kernel file descriptors and various other process state, and handle all the inheritance of process settings like signal handlers and process identity.

The process clone itself is handled within the kernel, but the fork implementation is actually implemented in an overridden CRT fork implementation. The stack duplication is an example of what is done in user space, versus the clone which happens in the kernel.

 With the single address space being shared between the parent and all forked children (and forks of forked children) there are a number of issues that can arise.
 The single address space causes the same global variables in the parent to be shared with the children, meaning changes made by one of the processes will affect the other.
 The C runtime itself has many global variables, and these global variables (along with any application specific ones too) when changed may unexpectedly affect all the other applications sharing the same address space.
 One important one to note is that of the C runtime itself which would deinitialize the whole CRT on the first process exit causing a cascade of problems and crashes for all other processes.
 For this specific reason the deinitialization of the CRT needs to be deferred until the last process is exited. For this reason when a child forked process process exits the CRT cleanup code is skipped.
 Only the parent of all the forked processes will do a CRT deinitialization when exit() is called.
 This can cause cleanup code that has been queued up for atexit to not run when the application is exited, and may be run (with unspecified behaviour) when the main process exits.
 To make sure the CRT is only cleaned up by the first process in a fork chain of processes this process needs to either kill all child processes on exit, or wait for them all to finish.
 This is achieved with the fork implementation chosen.

 The shared address space also causes problems for the copying of the parents stack into the child.
 The new child stack has all the frame pointers updated such that a stack walk can be achieved in the current stack, any stack variables that may point to other stack variables on the same stack will be incorrect and will point to the parents stack. One  way to achieve this is to search the space on the stack where function parameters and stack variables reside and fix them up, but this is potentially error prone and may cause fixup of other random values on the stack. Therefore these stack pointers are not currently being fixed up.

 Another problem with shared address space is related to the return of the fork() command. The parent may allocate some memory that will be used in the child forked process, but when fork() returns to continue execution the parent may delete this memory, causing the child forked process to use memory after it is freed. For this reason the safest model may be to only support a strict fork/exec model where the parent waits for the child to execute a new process through one of the exec*() APIs. This mode of operation is enabled through the fork configuration.

Because the pseudo fork syscall is not a real fork implementation and thus is not immune from data corruptions, the application needs to opt-in to use it. This is done with a new entry in the application config.json that is used for signing and packaging, or via the command line for non-signed testing.

| Name | Value |
| -- | -- |
| ForkMode | Enable different modes of operation for the fork() syscall. <br> **pseudo_wait_for_children**: (not yet implemented) Creates fork sharing parent address space and the parent process will wait for all forked children to shutdown before shutting down itself. <br> **pseudo_kill_children** - similar to the previous except when the parent is shutting down it will send a SIGKILL to all child fork processes and wait for all of them to exit. <br> **pseudo_wait_for_exit_exec** - the parent process will wait for the child forked process to call exec*() or exit() before continuing. This is similar to vfork() implementation except the forked process does get its own copy of the stack. <br> **none** - fork is disabled and returns a ENOTSUPP error if called.|
| | |
