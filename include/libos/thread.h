#ifndef _LIBOS_THREAD_H
#define _LIBOS_THREAD_H

#include <unistd.h>

#include <libos/assume.h>
#include <libos/setjmp.h>
#include <libos/tcall.h>
#include <libos/types.h>

#define LIBOS_THREAD_MAGIC 0xc79c53d9ad134ad4

/* indicates that vsbase has been set */
#define VSBASE_MAGIC 0xa992961d

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
    uint64_t tsd; /* thread pointer: unused by musl libc and Open Enclave */
    uint64_t reserved5;
    uint64_t reserved6;
    int errnum; /* errno: unused Open Enclave */
    int padding; /* unused by Open Enclave */
};

bool libos_valid_td(const void* td);

struct libos_thread
{
    uint64_t magic;

    /* used by libos_thread_queue_t */
    struct libos_thread* qnext;

    /* used by the active-list or the zombie-list */
    struct libos_thread* next;

    /* thread id passed by target */
    pid_t tid;

    /* synchronization event passed in by the target (example: futex uaddr) */
    uint64_t event;

    /* arguments passed to libos_syscall_clone() (unused by main thread)  */
    int (*fn)(void*);
    void* child_stack;
    int flags;
    void* arg;
    pid_t* ptid;
    libos_td_t* crt_td; /* same as newtls clone() argument */
    pid_t* ctid;

    /* called by target to run child theads */
    long (*run_thread)(uint64_t cookie, uint64_t event);

    /* pointer to the target and C-runtime thread descriptors */
    libos_td_t* target_td;

    /* for jumping back on exit */
    libos_jmp_buf_t jmpbuf;
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

static __inline__ size_t libos_thread_queue_size(libos_thread_queue_t* queue)
{
    size_t n = 0;

    for (libos_thread_t* p = queue->front; p; p = p->qnext)
        n++;

    return n;
}

static __inline__ void libos_thread_queue_push_back(
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

static __inline__ libos_thread_t* libos_thread_queue_pop_front(
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

static __inline__ bool libos_thread_queue_contains(
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

static __inline__ bool libos_thread_queue_empty(libos_thread_queue_t* queue)
{
    return queue->front ? false : true;
}

long libos_run_thread(uint64_t cookie, uint64_t event);

pid_t libos_generate_tid(void);

pid_t libos_gettid(void);

/* check that the thread descriptor refers to a vsbase */
int libos_check_vsbase(void);

#endif /* _LIBOS_THREAD_H */
