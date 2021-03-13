#include <limits.h>
#include <sys/mman.h>

#include <myst/printf.h>
#include <myst/crash.h>
#include <myst/list.h>
#include <myst/mmanutils.h>
#include <myst/kernel.h>
#include <myst/backtrace.h>
#include <myst/panic.h>

static void _dlmalloc_abort(void)
{
    myst_panic("dlmalloc failed");
}

static int _dlmalloc_sched_yield(void)
{
    __asm__ __volatile__("pause" : : : "memory");
    return 0;
}

static void* _dlmalloc_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    long r = (long)myst_mmap(addr, length, prot, flags, fd, offset);

    if (r < 0)
    {
        errno = -r;
        return MAP_FAILED;
    }

    return (void*)r;
}

static void* _dlmalloc_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    ...)
{
    /* ATTN: new_address is ignored */
    long r = (long)myst_mremap(old_address, old_size, new_size, flags, NULL);

    if (r < 0)
    {
        errno = -r;
        return MAP_FAILED;
    }

    return (void*)r;
}

static int _dlmalloc_munmap(void* addr, size_t length)
{
    int ret;

    if ((ret = myst_munmap(addr, length)) < 0)
    {
        errno = -ret;
        ret = -1;
    }

    return ret;
}

#define abort _dlmalloc_abort
#define sched_yield _dlmalloc_sched_yield
#define mmap _dlmalloc_mmap
#define mremap _dlmalloc_mremap
#define munmap _dlmalloc_munmap
#define USE_LOCKS 1
#define HAVE_MORECORE 0
#define malloc_getpagesize PAGE_SIZE
#define MORECORE_CONTIGUOUS 0
#define fprintf(STREAM, ...) myst_eprintf(__VA_ARGS__)
#define USE_DL_PREFIX 0

#include "../third_party/dlmalloc/malloc.c"

#define MAX_BACKTRACE_ADDRS 16

#ifdef MYST_ENABLE_LEAK_CHECKER
static myst_list_t _list;
static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;
#endif

static myst_malloc_stats_t _malloc_stats;

#ifdef MYST_ENABLE_LEAK_CHECKER
typedef struct node
{
    myst_list_node_t base;
    void* ptr;
    size_t size;
    void* addrs[MAX_BACKTRACE_ADDRS];
    size_t num_addrs;
} node_t;
#endif

#ifdef MYST_ENABLE_LEAK_CHECKER
static node_t* _new_node(void* ptr, size_t size)
{
    node_t* p;

    if (!(p = dlmalloc(sizeof(node_t))))
        return NULL;

    p->ptr = ptr;
    p->size = size;
    p->num_addrs = myst_backtrace(p->addrs, MYST_COUNTOF(p->addrs));

    return p;
}
#endif

#ifdef MYST_ENABLE_LEAK_CHECKER
static int _add_node(void* ptr, size_t size)
{
    node_t* node;

    if (!(node = _new_node(ptr, size)))
        return -1;

    myst_spin_lock(&_lock);
    {
        myst_list_append(&_list, (myst_list_node_t*)node);
        _malloc_stats.usage += size;

        if (_malloc_stats.usage > _malloc_stats.peak_usage)
            _malloc_stats.peak_usage = _malloc_stats.usage;
    }
    myst_spin_unlock(&_lock);

    return 0;
}
#endif

#ifdef MYST_ENABLE_LEAK_CHECKER
static int _remove_node(void* ptr)
{
    node_t* node = NULL;

    myst_spin_lock(&_lock);
    {
        for (myst_list_node_t* p = _list.head; p; p = p->next)
        {
            node_t* tmp = (node_t*)p;

            if (tmp->ptr == ptr)
            {
                node = tmp;
                _malloc_stats.usage -= node->size;
                myst_list_remove(&_list, p);
                break;
            }
        }
    }
    myst_spin_unlock(&_lock);

    if (node)
    {
        dlfree(node);
        return 0;
    }

    return -1;
}
#endif

void* malloc(size_t size)
{
    void* p = NULL;

    if (!(p = dlmalloc(size)))
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* calloc(size_t nmemb, size_t size)
{
    void* p = NULL;

    if (!(p = dlcalloc(nmemb, size)))
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    size_t n = nmemb * size;
    if (_add_node(p, n) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* realloc(void* ptr, size_t size)
{
    void* p = NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        myst_panic("unexpected");
#endif

    if (!(p = dlrealloc(ptr, size)))
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* memalign(size_t alignment, size_t size)
{
    void* p = NULL;

    if (!(p = dlmemalign(alignment, size)))
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void free(void* ptr)
{
    dlfree(ptr);

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        myst_panic("unexpected");
#endif
}

int myst_find_leaks(void)
{
#ifdef MYST_ENABLE_LEAK_CHECKER
    int ret = 0;

    for (myst_list_node_t* p = _list.head; p; p = p->next)
    {
        node_t* node = (node_t*)p;

        myst_eprintf(
            "*** kernel leak: ptr=%p size=%zu\n", node->ptr, node->size);
        myst_dump_backtrace(node->addrs, node->num_addrs);
        myst_eprintf("\n");
        ret = -1;
    }

    if (_malloc_stats.usage != 0)
    {
        myst_eprintf(
            "*** kernel: memory still in use: %zu\n", _malloc_stats.usage);
        ret = -1;
    }

    return ret;
#else
    return 0;
#endif
}

int myst_get_malloc_stats(myst_malloc_stats_t* stats)
{
#ifdef MYST_ENABLE_LEAK_CHECKER
    {
        if (!stats)
            return -EINVAL;

        myst_spin_lock(&_lock);
        *stats = _malloc_stats;
        myst_spin_unlock(&_lock);

        return 0;
    }
#else
    (void)stats;
    (void)_malloc_stats;
    return -ENOTSUP;
#endif
}
