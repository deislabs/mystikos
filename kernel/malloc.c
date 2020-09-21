#include <libos/crash.h>
#include <libos/list.h>
#include <libos/malloc.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/tcall.h>
#include <libos/thread.h>

static libos_list_t _list;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

typedef struct node
{
    libos_list_node_t base;
    void* __ptr;
    size_t size;
    const char* file;
    size_t line;
    const char* func;
} node_t;

static libos_malloc_stats_t _malloc_stats;

long libos_tcall_allocate(
    void* ptr,
    size_t alignment,
    size_t size,
    int clear,
    void** new_ptr)
{
    long params[6];
    params[0] = (long)ptr;
    params[1] = (long)alignment;
    params[2] = (long)size;
    params[3] = (long)clear;
    params[4] = (long)new_ptr;

    return libos_tcall(LIBOS_TCALL_ALLOCATE, params);
}

long libos_tcall_deallocate(void* ptr)
{
    long params[6];
    params[0] = (long)ptr;

    return libos_tcall(LIBOS_TCALL_DEALLOCATE, params);
}

#ifdef LIBOS_ENABLE_LEAK_CHECKER
static node_t* _new_node(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    node_t* p;

    if (libos_tcall_allocate(NULL, 0, sizeof(node_t), 0, (void**)&p) != 0 || !p)
        return NULL;

    p->__ptr = ptr;
    p->size = size;
    p->file = file;
    p->line = line;
    p->func = func;

    return p;
}
#endif

#ifdef LIBOS_ENABLE_LEAK_CHECKER
static int _add_node(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    node_t* node;

    if (!(node = _new_node(ptr, size, file, line, func)))
        return -1;

    libos_spin_lock(&_lock);
    {
        libos_list_append(&_list, (libos_list_node_t*)node);
        _malloc_stats.usage += size;

        if (_malloc_stats.usage > _malloc_stats.peak_usage)
            _malloc_stats.peak_usage = _malloc_stats.usage;
    }
    libos_spin_unlock(&_lock);

    return 0;
}
#endif

#ifdef LIBOS_ENABLE_LEAK_CHECKER
static int _remove_node(void* ptr)
{
    node_t* node = NULL;

    libos_spin_lock(&_lock);
    {
        for (libos_list_node_t* p = _list.head; p; p = p->next)
        {
            node_t* tmp = (node_t*)p;

            if (tmp->__ptr == ptr)
            {
                node = tmp;
                _malloc_stats.usage -= node->size;
                libos_list_remove(&_list, p);
                break;
            }
        }
    }
    libos_spin_unlock(&_lock);

    if (node)
    {
        libos_tcall_deallocate(node);
        return 0;
    }

    return -1;
}
#endif

void* __libos_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    void* p = NULL;
    (void)file;
    (void)line;
    (void)func;

    if (libos_tcall_allocate(NULL, 0, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        libos_panic("unexpected");
#endif

    return p;
}

void* __libos_calloc(
    size_t nmemb,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    void* p = NULL;
    size_t n = nmemb * size;
    (void)file;
    (void)line;
    (void)func;

    if (libos_tcall_allocate(NULL, 0, n, 1, &p) != 0 || !p)
        return NULL;

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (_add_node(p, n, file, line, func) != 0)
        libos_panic("unexpected");
#endif

    return p;
}

void* __libos_realloc(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    void* p = NULL;
    (void)file;
    (void)line;
    (void)func;

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        libos_panic("unexpected");
#endif

    if (libos_tcall_allocate(ptr, 0, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        libos_panic("unexpected");
#endif

    return p;
}

void* __libos_memalign(
    size_t alignment,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    void* p = NULL;
    (void)file;
    (void)line;
    (void)func;

    if (libos_tcall_allocate(NULL, alignment, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        libos_panic("unexpected");
#endif

    return p;
}

void __libos_free(void* ptr, const char* file, size_t line, const char* func)
{
    (void)file;
    (void)line;
    (void)func;

    if (libos_tcall_deallocate(ptr) != 0)
        libos_panic("unexpected");

#ifdef LIBOS_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        libos_panic("unexpected");
#endif
}

int libos_find_leaks(void)
{
    int ret = 0;

    for (libos_list_node_t* p = _list.head; p; p = p->next)
    {
        node_t* node = (node_t*)p;

        libos_eprintf(
            "*********** kernel leak: %s(%zu): %s(): ptr=%p size=%zu\n",
            node->file,
            node->line,
            node->func,
            node->__ptr,
            node->size);

        ret = -1;
    }

    if (_malloc_stats.usage != 0)
    {
        libos_eprintf(
            "********** kernel: memory still in use: %zu\n",
            _malloc_stats.usage);
        ret = -1;
    }

    return ret;
}

int libos_get_malloc_stats(libos_malloc_stats_t* stats)
{
#ifdef LIBOS_ENABLE_LEAK_CHECKER
    {
        if (!stats)
            return -EINVAL;

        libos_spin_lock(&_lock);
        *stats = _malloc_stats;
        libos_spin_unlock(&_lock);

        return 0;
    }
#else
    (void)stats;
    (void)_malloc_stats;
    return -ENOTSUP;
#endif
}
