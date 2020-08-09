#ifndef _POSIX_THREAD_H
#define _POSIX_THREAD_H

#include <stdint.h>
#include <setjmp.h>
#include <unistd.h>
#include <stdbool.h>
#include "posix_ocall_structs.h"
#include "posix_spinlock.h"

typedef struct _posix_thread posix_thread_t;
typedef struct _posix_mutex posix_mutex_t;

struct posix_robust_list_head
{
    volatile void* volatile head;
};

#define POSIX_THREAD_STATE_STARTED 0xAAAABBBB

struct _posix_thread
{
    /* Should contain MAGIC */
    uint32_t magic;

    posix_thread_t* next;
    posix_thread_t* prev;

    /* Pointer to MUSL pthread structure */
    struct pthread* td;

    /* The fn parameter from posix_clone() */
    int (*fn)(void*);

    /* The arg parameter from posix_clone() */
    void* arg;

    /* The flags parameter from posix_clone() */
    int flags;

    /* The ptid parameter from posix_clone() */
    pid_t* ptid;

    /* The ctid parameter from posix_clone() (__thread_list_lock) */
    volatile pid_t* ctid;

    /* Used to jump from posix_exit() back to posix_run_thread_ecall() */
    jmp_buf jmpbuf;

    /* Address of the host thread's shared page */
    struct posix_shared_block* shared_block;

    /* TID passed to posix_run_thread_ecall() */
    int tid;

    /* Robust list support */
    struct posix_robust_list_head* robust_list_head;
    size_t robust_list_len;

    /* Spin here until thread is actually created */
    posix_spinlock_t lock;

    uint32_t state;
};

typedef struct _posix_thread_queue
{
    posix_thread_t* front;
    posix_thread_t* back;
} posix_thread_queue_t;

static __inline__ size_t posix_thread_queue_size(posix_thread_queue_t* queue)
{
    size_t n = 0;

    for (posix_thread_t* p = queue->front; p; p = p->next)
        n++;

    return n;
}

static __inline__ void posix_thread_queue_push_back(
    posix_thread_queue_t* queue,
    posix_thread_t* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

static __inline__ posix_thread_t* posix_thread_queue_pop_front(
    posix_thread_queue_t* queue)
{
    posix_thread_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->next;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

static __inline__ bool posix_thread_queue_contains(
    posix_thread_queue_t* queue,
    posix_thread_t* thread)
{
    posix_thread_t* p;

    for (p = queue->front; p; p = p->next)
    {
        if (p == thread)
            return true;
    }

    return false;
}

static __inline__ bool posix_thread_queue_empty(
    posix_thread_queue_t* queue)
{
    return queue->front ? false : true;
}

posix_thread_t* posix_self(void);

int posix_set_tid_address(int* tidptr);

int posix_set_thread_area(void* p);

int posix_clone(
    int (*fn)(void *),
    void* child_stack,
    int flags,
    void* arg,
    ...);

void posix_force_exit(int status);

int posix_gettid(void);

int posix_getpid(void);

long posix_get_robust_list(
    int pid,
    struct posix_robust_list_head** head_ptr,
    size_t* len_ptr);

long posix_set_robust_list(struct posix_robust_list_head* head, size_t len);

int posix_tkill(int tid, int sig);

void posix_noop(void);

void posix_exit(int status);

void posix_unblock_creator_thread(void);

#endif /* _POSIX_THREAD_H */
