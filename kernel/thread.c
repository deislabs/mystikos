#include <libos/assert.h>
#include <libos/atexit.h>
#include <libos/atomic.h>
#include <libos/eraise.h>
#include <libos/fsgs.h>
#include <libos/futex.h>
#include <libos/lfence.h>
#include <libos/malloc.h>
#include <libos/options.h>
#include <libos/setjmp.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/tcall.h>
#include <libos/thread.h>
#include <libos/trace.h>
#include <libos/ud2.h>

libos_thread_t* __libos_main_thread;

/*
**==============================================================================
**
** TID generation
**
**     Generate thread ids rather than depending on the ones provided by the
**     target.
**
**==============================================================================
*/

#define MIN_TID 100

pid_t libos_generate_tid(void)
{
    static pid_t _tid = MIN_TID;
    static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;
    pid_t tid;

    libos_spin_lock(&_lock);
    {
        if (_tid < MIN_TID)
            _tid = MIN_TID;

        tid = _tid++;
    }
    libos_spin_unlock(&_lock);

    return tid;
}

/*
**==============================================================================
**
** cookie map:
**
**     This structure maps cookies to threads. When a thread is created, the
**     kernel passes a cookie to the target (libos_tcall_create_thread).
**     The host creates a new thread and then calls back into the kernel on
**     that thread (libos_run_thread). Rather than passing a thread pointer
**     directly to the target, we pass a cookie instead. A mapping only exists
**     while a new thread is being created and deleted from the map immediately
**     after the thread enters the kernel. The map provides functions for
**     adding and removing a mapping.
**
**     A cookie is a 64-bit integer whose upper 32-bits are an index into the
**     cookie map array, and the lower 32-bits are a random integer.
**
**     The cookie map provides two operations:
**         _get_cookie() -- assigns and returns a cookie for the thread pointer.
**         _put_cookie() -- deletes a cookie and returns the thread pointer.
**
**     Both operations are O(1)
**
**==============================================================================
*/

#define MAX_COOKIE_MAP_ENTRIES 64

typedef struct cookie_map_entry
{
    uint64_t cookie;
    libos_thread_t* thread;
    size_t next1; /* one-based next pointer */
} cookie_map_entry_t;

static cookie_map_entry_t _cookie_map[MAX_COOKIE_MAP_ENTRIES];
static size_t _cookie_map_next;  /* next available entry */
static size_t _cookie_map_free1; /* free list of cookie entries (one-based) */
static libos_spinlock_t _cookie_map_lock;

/* assign a cookie for the given thread pointer and return the cookie */
static uint64_t _get_cookie(libos_thread_t* thread)
{
    uint32_t rand;
    uint64_t cookie;

    /* generate a random number */
    if (libos_syscall_getrandom(&rand, sizeof(rand), 0) != sizeof(rand))
        libos_panic("getrandom failed");

    /* add a new entry to the cookie map */
    libos_spin_lock(&_cookie_map_lock);
    {
        uint32_t index;

        if (_cookie_map_next < MAX_COOKIE_MAP_ENTRIES)
        {
            index = (uint32_t)_cookie_map_next++;
        }
        else if (_cookie_map_free1 != 0)
        {
            /* take first entry on the free list (adjust to zero-based) */
            index = (uint32_t)(_cookie_map_free1 - 1);

            /* remove this entry from the free list */
            _cookie_map_free1 = _cookie_map[index].next1;
        }
        else
        {
            libos_panic("cookie map exhausted");
        }

        cookie = ((uint64_t)index << 32) | (uint64_t)rand;

        _cookie_map[index].cookie = cookie;
        _cookie_map[index].thread = thread;
        _cookie_map[index].next1 = 0;
    }
    libos_spin_unlock(&_cookie_map_lock);

    return cookie;
}

/* fetch the cookie form the cookie map, while deleting the entry */
static libos_thread_t* _put_cookie(uint64_t cookie)
{
    uint32_t index;
    libos_thread_t* thread = NULL;

    if (cookie == 0)
        libos_panic("zero-valued cookie");

    libos_lfence();

    /* extract the index from the cookie */
    index = (uint32_t)((cookie & 0xffffffff00000000) >> 32);

    libos_spin_lock(&_cookie_map_lock);
    {
        if (index >= _cookie_map_next)
            libos_panic("bad cookie index");

        if (_cookie_map[index].cookie != cookie)
            libos_panic("cookie mismatch");

        thread = _cookie_map[index].thread;

        /* clear the entry */
        _cookie_map[index].cookie = 0;
        _cookie_map[index].thread = NULL;

        /* add the entry to the free list */
        _cookie_map[index].next1 = _cookie_map_free1;
        _cookie_map_free1 = index + 1;
    }
    libos_spin_unlock(&_cookie_map_lock);

    return thread;
}

/*
**==============================================================================
**
** zombie list implementation:
**
**     Threads are moved onto the zombie list after exiting. We suspect that
**     that synchronizing threads may need access in the future to the thread
**     structure after the thread has exited (e.g., to retieve the exit
*status).**     This assumption may turn out to be false, in which case the
*zombie list
**     could be removed.
**
**==============================================================================
*/

static libos_thread_t* _zombies;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

static void _free_zombies(void* arg)
{
    libos_thread_t* p;

    (void)arg;

    for (p = _zombies; p;)
    {
        libos_thread_t* next = p->next;

        libos_memset(p, 0xdd, sizeof(libos_thread_t));
        libos_free(p);

        p = next;
    }

    _zombies = NULL;
}

void libos_zombify_thread(libos_thread_t* thread)
{
    libos_spin_lock(&_lock);
    {
        static bool _initialized;

        if (!_initialized)
        {
            libos_atexit(_free_zombies, NULL);
            _initialized = true;
        }

        thread->next = _zombies;
        _zombies = thread;
    }
    libos_spin_unlock(&_lock);
}

/*
**==============================================================================
**
** main thread implementation:
**
**==============================================================================
*/

bool libos_valid_td(const void* td)
{
    return td && ((const libos_td_t*)td)->self == td;
}

static bool _valid_thread(const libos_thread_t* thread)
{
    return thread && thread->magic == LIBOS_THREAD_MAGIC;
}

static void _call_thread_fn(void)
{
    libos_thread_t* thread = libos_get_vsbase();

    libos_assert(thread != NULL);
    thread->fn(thread->arg);
}

/* The target calls this from the new thread */
long libos_run_thread(uint64_t cookie, uint64_t event)
{
    libos_thread_t* thread = (libos_thread_t*)_put_cookie(cookie);
    libos_td_t* td;
    libos_td_t* old_td = libos_get_fsbase();

    libos_assert(libos_valid_td(old_td));

    if (__options.have_syscall_instruction)
        libos_set_gsbase(old_td);

    if (!_valid_thread(thread))
        return -EINVAL;

    if (!libos_valid_td(td = thread->newtls))
        libos_panic("invalid td");

    /* propagate the canary */
    td->canary = old_td->canary;

    thread->tid = libos_generate_tid();
    thread->event = event;
    thread->original_fsbase = old_td;

    /* initialize the vsbase */
    td->vsbase.magic = VSBASE_MAGIC;
    td->vsbase.index1 = 0;

    /* set the fsbase to the libc thread */
    libos_set_fsbase(td);
    libos_set_vsbase(thread);

    /* Set the TID for this thread (sets the td tid field) */
    libos_atomic_exchange(thread->ptid, thread->tid);

    /* Jump back here from exit */
    if (libos_setjmp(&thread->jmpbuf) != 0)
    {
        libos_assert(libos_gettid() != -1);

        /* Wake up any thread waiting on ctid */
        {
            libos_atomic_exchange(thread->ctid, 0);
            const int futex_op = FUTEX_WAKE | FUTEX_PRIVATE;
            libos_syscall_futex(thread->ctid, futex_op, 1, 0, NULL, 0);
        }

        /* restore the original fsbase */
        libos_put_vsbase();
        libos_set_fsbase(thread->original_fsbase);

        libos_zombify_thread(thread);
    }
    else
    {
#ifdef LIBOS_USE_THREAD_STACK
        libos_jmp_buf_t env = thread->jmpbuf;

        env.rip = (uint64_t)_call_thread_fn;
        env.rsp = (uint64_t)thread->child_stack;
        env.rbp = (uint64_t)thread->child_stack;
        libos_jump(&env);
#else
        (*thread->fn)(thread->arg);
        (void)_call_thread_fn;
#endif
        /* unreachable */
    }

    return 0;
}

static long _syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid)
{
    long ret = 0;
    uint64_t cookie = 0;
    libos_thread_t* thread;

    if (!fn)
        ERAISE(-EINVAL);

    if (!libos_valid_td(newtls))
        ERAISE(-EINVAL);

    /* Create and initialize the thread struct */
    {
        if (!(thread = libos_calloc(1, sizeof(libos_thread_t))))
            ERAISE(-ENOMEM);

        thread->magic = LIBOS_THREAD_MAGIC;
        thread->fn = fn;
        thread->child_stack = child_stack;
        thread->flags = flags;
        thread->arg = arg;
        thread->ptid = ptid;
        thread->newtls = newtls;
        thread->ctid = ctid;
        thread->run_thread = libos_run_thread;
    }

    cookie = _get_cookie(thread);

    if (libos_tcall_create_thread(cookie) != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

long libos_syscall_clone(
    int (*fn)(void*),
    void* child_stack,
    int flags,
    void* arg,
    pid_t* ptid,
    void* newtls,
    pid_t* ctid)
{
    return _syscall_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);
}

pid_t libos_gettid(void)
{
    libos_thread_t* thread;

    if (libos_check_vsbase() != 0)
        return -1;

    thread = libos_get_vsbase();
    libos_assert(thread != NULL);

    return thread->tid;
}

/*
**==============================================================================
**
** vsbase
**
**==============================================================================
*/

#define MAX_VSBASES 1024

typedef struct vsbase_entry
{
    void* vsbase;
    uint32_t next; /* one-based index; zero signifies null */
} vsbase_entry_t;

static vsbase_entry_t _vsbases[MAX_VSBASES];
static uint32_t _vsbases_next;  /* next available (zero-based) */
static uint32_t _vsbases_free1; /* linked list (one-based) */
static libos_spinlock_t _vsbases_lock;

/* retrieves the vsbase in O(1) */
void libos_set_vsbase(void* p)
{
    libos_td_t* td = libos_get_fsbase();

    libos_assert(libos_valid_td(td));

    libos_spin_lock(&_vsbases_lock);
    {
        uint32_t index1 = 0; /* one-based */

        if (td->vsbase.magic != VSBASE_MAGIC)
            libos_panic("bad magic");

        if (td->vsbase.index1 != 0)
            libos_panic("already in use");

        if (_vsbases_next != MAX_VSBASES)
        {
            index1 = (uint32_t)(_vsbases_next++ + 1);
        }
        else
        {
            if (_vsbases_free1 == 0)
                libos_panic("exhausted vsbase table");

            /* get next free entry */
            index1 = _vsbases_free1;

            /* remove this entry from the free list */
            _vsbases_free1 = _vsbases[index1 - 1].next;
        }

        if (index1 == 0)
            libos_panic("exhausted vsbase table");

        _vsbases[index1 - 1].vsbase = p;
        _vsbases[index1 - 1].next = 0;
        td->vsbase.index1 = index1;
    }
    libos_spin_unlock(&_vsbases_lock);
}

/* releases the vsbase in O(1) */
void* libos_put_vsbase(void)
{
    libos_td_t* td = libos_get_fsbase();
    void* vsbase = NULL;

    libos_assert(libos_valid_td(td));

    libos_spin_lock(&_vsbases_lock);
    {
        uint32_t index1; /* one-based */

        if (td->vsbase.magic != VSBASE_MAGIC)
            libos_panic("bad vsbase magic");

        index1 = (uint32_t)td->vsbase.index1;

        if (index1 == 0)
            libos_panic("null vsbase");

        if (index1 > MAX_VSBASES)
            libos_panic("bad vsbase index");

        /* set index to null */
        td->vsbase.index1 = 0;

        _vsbases[index1 - 1].next = _vsbases_free1;
        _vsbases_free1 = index1;
    }
    libos_spin_unlock(&_vsbases_lock);

    return vsbase;
}

/* releases the vsbase in O(1) */
void* libos_get_vsbase(void)
{
    libos_td_t* td = libos_get_fsbase();
    void* vsbase = NULL;

    libos_assert(libos_valid_td(td));

    libos_spin_lock(&_vsbases_lock);
    {
        uint32_t index1; /* one-based */

        if (td->vsbase.magic != VSBASE_MAGIC)
            libos_panic("bad vsbase magic");

        index1 = td->vsbase.index1;

        if (index1 == 0)
            libos_panic("null vsbase");

        if (index1 > MAX_VSBASES)
            libos_panic("bad vsbase index");

        vsbase = _vsbases[index1 - 1].vsbase;
    }
    libos_spin_unlock(&_vsbases_lock);

    return vsbase;
}

int libos_check_vsbase(void)
{
    int ret = -1;
    libos_td_t* td = libos_get_fsbase();

    libos_assert(libos_valid_td(td));

    libos_spin_lock(&_vsbases_lock);
    {
        if (td->vsbase.magic == VSBASE_MAGIC)
            ret = 0;
    }
    libos_spin_unlock(&_vsbases_lock);

    return ret;
}
