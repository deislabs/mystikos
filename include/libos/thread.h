// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_THREAD_H
#define _LIBOS_THREAD_H

#include <unistd.h>

#include <libos/assume.h>
#include <libos/defs.h>
#include <libos/fdtable.h>
#include <libos/setjmp.h>
#include <libos/tcall.h>
#include <libos/types.h>

#define LIBOS_THREAD_MAGIC 0xc79c53d9ad134ad4

typedef struct libos_thread libos_thread_t;

typedef struct libos_td libos_td_t;

/* thread descriptor for libc threads (initial fields of struct pthread) */
struct libos_td
{
    struct libos_td* self;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
    uint64_t canary;
    uint64_t tsd; /* pointer to libos_thread_t (within OE gsbase) */
    uint64_t reserved5;
    uint64_t reserved6;
    int errnum;  /* errno: unused Open Enclave */
    int padding; /* unused by Open Enclave */
};

bool libos_valid_td(const void* td);

struct libos_thread
{
    /* LIBOS_THREAD_MAGIC */
    uint64_t magic;

    /* used by libos_thread_queue_t (condition variables and mutexes) */
    struct libos_thread* qnext;

    /* used by zombie-list */
    struct libos_thread* next;

    /* the session id (see getsid() function) */
    pid_t sid;

    /* the parent process identifier (inherited from main thread) */
    pid_t ppid;

    /* the process identifier (inherited from main thread) */
    pid_t pid;

    /* unique thread identifier (same as pid for main thread) */
    pid_t tid;

    /* The exit status passed to SYS_exit */
    int exit_status;

    /* the C-runtime thread descriptor */
    libos_td_t* crt_td;

    /* the target and thread descriptor */
    libos_td_t* target_td;

    /* called by target to run child theads */
    long (*run_thread)(uint64_t cookie, uint64_t event);

    /* synchronization event from libos_thread_t.run_thread() */
    uint64_t event;

    /* for jumping back on exit */
    libos_jmp_buf_t jmpbuf;

    /* the file-descriptor table is inherited from process thread */
    libos_fdtable_t* fdtable;

    /* arguments passed in from SYS_clone */
    struct
    {
        int (*fn)(void*);
        void* child_stack;
        int flags;
        void* arg;
        pid_t* ptid;  /* null for vfork */
        void* newtls; /* null for vfork */
        pid_t* ctid;  /* null for vfork */
    } clone;

    /* fields used by main thread (process thread) */
    struct
    {
        /* the stack that was created by libos_exec() */
        void* exec_stack;

        /* the copy of the CRT data made by libos_exec() */
        void* exec_crt_data;
        size_t exec_crt_size;
    } main;
};

LIBOS_INLINE bool libos_valid_thread(const libos_thread_t* thread)
{
    return thread && thread->magic == LIBOS_THREAD_MAGIC;
}

libos_thread_t* libos_thread_self(void);

void libos_zombify_thread(libos_thread_t* thread);

extern libos_thread_t* __libos_main_thread;

typedef struct libos_thread_queue
{
    libos_thread_t* front;
    libos_thread_t* back;
} libos_thread_queue_t;

LIBOS_INLINE size_t libos_thread_queue_size(libos_thread_queue_t* queue)
{
    size_t n = 0;

    for (libos_thread_t* p = queue->front; p; p = p->qnext)
        n++;

    return n;
}

LIBOS_INLINE void libos_thread_queue_push_back(
    libos_thread_queue_t* queue,
    libos_thread_t* thread)
{
    thread->qnext = NULL;

    if (queue->back)
        queue->back->qnext = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

LIBOS_INLINE libos_thread_t* libos_thread_queue_pop_front(
    libos_thread_queue_t* queue)
{
    libos_thread_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->qnext;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

LIBOS_INLINE bool libos_thread_queue_contains(
    libos_thread_queue_t* queue,
    libos_thread_t* thread)
{
    libos_thread_t* p;

    for (p = queue->front; p; p = p->qnext)
    {
        if (p == thread)
            return true;
    }

    return false;
}

LIBOS_INLINE bool libos_thread_queue_empty(libos_thread_queue_t* queue)
{
    return queue->front ? false : true;
}

LIBOS_INLINE bool libos_is_process_thread(const libos_thread_t* thread)
{
    return thread && thread->pid == thread->tid;
}

long libos_run_thread(uint64_t cookie, uint64_t event);

pid_t libos_generate_tid(void);

pid_t libos_gettid(void);

void libos_wait_on_child_processes(void);

int libos_get_num_threads(void);

#endif /* _LIBOS_THREAD_H */
