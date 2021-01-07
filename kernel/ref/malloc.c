// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/crash.h>
#include <myst/list.h>
#include <myst/malloc.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

static myst_list_t _list;
static myst_spinlock_t _lock = MYST_SPINLOCK_INITIALIZER;

typedef struct node
{
    myst_list_node_t base;
    void* __ptr;
    size_t size;
    const char* file;
    size_t line;
    const char* func;
} node_t;

static myst_malloc_stats_t _malloc_stats;

long myst_tcall_allocate(
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

    return myst_tcall(MYST_TCALL_ALLOCATE, params);
}

long myst_tcall_deallocate(void* ptr)
{
    long params[6];
    params[0] = (long)ptr;

    return myst_tcall(MYST_TCALL_DEALLOCATE, params);
}

#ifdef MYST_ENABLE_LEAK_CHECKER
static node_t* _new_node(
    void* ptr,
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    node_t* p;

    if (myst_tcall_allocate(NULL, 0, sizeof(node_t), 0, (void**)&p) != 0 || !p)
        return NULL;

    p->__ptr = ptr;
    p->size = size;
    p->file = file;
    p->line = line;
    p->func = func;

    return p;
}
#endif

#ifdef MYST_ENABLE_LEAK_CHECKER
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

            if (tmp->__ptr == ptr)
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
        myst_tcall_deallocate(node);
        return 0;
    }

    return -1;
}
#endif

void* __myst_malloc(
    size_t size,
    const char* file,
    size_t line,
    const char* func)
{
    void* p = NULL;
    (void)file;
    (void)line;
    (void)func;

    if (myst_tcall_allocate(NULL, 0, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* __myst_calloc(
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

    if (myst_tcall_allocate(NULL, 0, n, 1, &p) != 0 || !p)
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, n, file, line, func) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* __myst_realloc(
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

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        myst_panic("unexpected");
#endif

    if (myst_tcall_allocate(ptr, 0, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void* __myst_memalign(
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

    if (myst_tcall_allocate(NULL, alignment, size, 0, &p) != 0 || !p)
        return NULL;

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (_add_node(p, size, file, line, func) != 0)
        myst_panic("unexpected");
#endif

    return p;
}

void __myst_free(void* ptr, const char* file, size_t line, const char* func)
{
    (void)file;
    (void)line;
    (void)func;

    if (myst_tcall_deallocate(ptr) != 0)
        myst_panic("unexpected");

#ifdef MYST_ENABLE_LEAK_CHECKER
    if (ptr && _remove_node(ptr) != 0)
        myst_panic("unexpected");
#endif
}

int myst_find_leaks(void)
{
    int ret = 0;

    for (myst_list_node_t* p = _list.head; p; p = p->next)
    {
        node_t* node = (node_t*)p;

        myst_eprintf(
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
        myst_eprintf(
            "********** kernel: memory still in use: %zu\n",
            _malloc_stats.usage);
        ret = -1;
    }

    return ret;
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
