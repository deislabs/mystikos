#ifndef _LIBOS_THREAD_H
#define _LIBOS_THREAD_H

#include <libos/types.h>
#include <libos/setjmp.h>
#include <unistd.h>

#define LIBOS_THREAD_MAGIC 0xc79c53d9ad134ad4

typedef struct libos_thread libos_thread_t;

struct libos_thread
{
    uint64_t magic;

    /* arguments passed to libos_syscall_clone() */
    int (*fn)(void*);
    void* child_stack;
    int flags;
    void* arg;
    pid_t* ptid;
    void* newtls;
    pid_t* ctid;

    /* the new thread calls this from the target */
    long (*run)(libos_thread_t* thread);

    /* original fsbase (from the target) */
    const void* original_fsbase;

    /* for jumping back to kernel/thread.c:_run() */
    libos_jmp_buf_t jmpbuf;
};

int libos_add_thread(libos_thread_t* thread);

libos_thread_t* libos_find_thread(void);

libos_thread_t* libos_remove_thread(void);

#endif /* _LIBOS_THREAD_H */
