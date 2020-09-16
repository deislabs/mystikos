#ifndef _LIBOS_THREAD_H
#define _LIBOS_THREAD_H

#include <libos/setjmp.h>
#include <libos/types.h>
#include <libos/tcall.h>
#include <unistd.h>

#define LIBOS_THREAD_MAGIC 0xc79c53d9ad134ad4

/* indicates that vsbase has been set */
#define VSBASE_MAGIC 0xa992961d

/* thread descriptor: initial fields align with libc pthread ABI */
struct libos_td
{
    struct libos_td* self;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
    uint64_t canary;
    /* these eight bytes are unused in musl libc */
    struct
    {
        uint32_t magic; /* VSBASE_MAGIC */
        uint32_t index1; /* one-based index (zero indicates null vsbase) */
    }
    vsbase;
};

typedef struct libos_td libos_td_t;

bool libos_valid_td(const void* td);

typedef struct libos_thread libos_thread_t;

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
    void* newtls; /* thread pointer: same as pthread_self() in musl libc */
    pid_t* ctid;

    /* the new thread calls this from the target (unused by main thread) */
    long (*run)(libos_thread_t* thread, pid_t tid, uint64_t event);

    /* The original fsbase as given by target */
    void* original_fsbase;

    /* for jumping back on exit */
    libos_jmp_buf_t jmpbuf;
};

void libos_release_thread(libos_thread_t* thread);

size_t libos_get_num_active_threads(void);

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

long libos_run_thread(uint64_t cookie, pid_t tid, uint64_t event);

pid_t libos_gettid(void);

void libos_set_vsbase(void* p);

void* libos_put_vsbase(void);

void* libos_get_vsbase(void);

/* check that the thread descriptor refers to a vsbase */
int libos_check_vsbase(void);

#endif /* _LIBOS_THREAD_H */
