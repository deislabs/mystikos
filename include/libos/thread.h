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
    libos_thread_t* next;

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
    void* newtls;
    pid_t* ctid;

    /* the new thread calls this from the target (unused by main thread) */
    long (*run)(libos_thread_t* thread, pid_t tid, uint64_t event);

    /* The original fsbase as given by target */
    const void* original_fsbase;

    /* for jumping back on exit */
    libos_jmp_buf_t jmpbuf;
};

int libos_add_thread(libos_thread_t* thread);

libos_thread_t* libos_self(void);

libos_thread_t* libos_remove_thread(void);

typedef struct libos_thread_queue
{
    libos_thread_t* front;
    libos_thread_t* back;
} libos_thread_queue_t;

static __inline__ size_t libos_thread_queue_size(libos_thread_queue_t* queue)
{
    size_t n = 0;

    for (libos_thread_t* p = queue->front; p; p = p->next)
        n++;

    return n;
}

static __inline__ void libos_thread_queue_push_back(
    libos_thread_queue_t* queue,
    libos_thread_t* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
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
        queue->front = queue->front->next;

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

    for (p = queue->front; p; p = p->next)
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

#endif /* _LIBOS_THREAD_H */
