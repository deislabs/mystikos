#include <assert.h>
#include <bits/alltypes.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

#define weak_alias(old, new) \
    extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))

#define ENOMEM 12

__thread int errno;

const char* const sys_errlist[] = {};
const int sys_nerr = 0;

void __makecontext(ucontext_t* ucp, void (*func)(void), int argc, ...)
{
    assert(0);
}
weak_alias(__makecontext, makecontext);

int setcontext(const ucontext_t* ucp)
{
    assert(0);
    return -1;
}

typedef struct __mbstate_t
{
    unsigned __opaque1, __opaque2;
} mbstate_t;
size_t __mbrlen(const char* s, size_t n, mbstate_t* ps)
{
    assert(0);
    return -1;
}
weak_alias(__mbrlen, mbrlen);

int __openat_2(int fd, const char* file, int oflag)
{
    assert(0);
    return -1;
}

struct obstack
{
};

void _obstack_newchunk(struct obstack* h, int length)
{
    assert(0);
}

int __argz_create_sep(const char* string, int delim, char** argz, size_t* len)
{
    assert(0);
    return ENOMEM;
}
weak_alias(__argz_create_sep, argz_create_sep);

struct CLIENT
{
};

struct CLIENT* clnt_create(
    const char* hostname,
    unsigned long prog,
    unsigned long vers,
    const char* proto)
{
    assert(0);
    return NULL;
}

char* clnt_spcreateerror(const char* msg)
{
    assert(0);
    return NULL;
}

int __libc_mallopt(int param_number, int value)
{
    assert(0);
    return 0;
}
weak_alias(__libc_mallopt, mallopt);

int _IO_obstack_vprintf(
    struct obstack* obstack,
    const char* format,
    va_list args)
{
    assert(0);
    return -1;
}
weak_alias(_IO_obstack_vprintf, obstack_vprintf);

int __register_printf_modifier(const wchar_t* str)
{
    assert(0);
    return -1;
}
weak_alias(__register_printf_modifier, register_printf_modifier);

struct printf_info
{
};

typedef int printf_function(
    FILE* __stream,
    const struct printf_info* __info,
    const void* const* __args);

typedef int printf_arginfo_size_function(
    const struct printf_info* __info,
    size_t __n,
    int* __argtypes,
    int* __size);

int __register_printf_specifier(
    int spec,
    printf_function converter,
    printf_arginfo_size_function arginfo)
{
    assert(0);
    return -1;
}
weak_alias(__register_printf_specifier, register_printf_specifier);

typedef void printf_va_arg_function(void* __mem, va_list* __ap);
int __register_printf_type(printf_va_arg_function fct)
{
    assert(0);
    return -1;
}
weak_alias(__register_printf_type, register_printf_type);

typedef struct XDR
{
} XDR;

int xdr_enum(XDR* xdrs, int* ep)
{
    assert(0);
    return false;
}

typedef int (*xdrproc_t)(XDR*, void*, ...);

int xdr_pointer(
    XDR* xdrs,
    char** objpp,
    unsigned int obj_size,
    xdrproc_t xdr_obj)
{
    assert(0);
    return -1;
}

int xdr_string(XDR* xdrs, char** cpp, unsigned int maxsize)
{
    assert(0);
    return -1;
}

void __res_iclose(res_state statp, bool free_addr)
{
    assert(0);
}

struct resolv_context
{
};

struct resolv_context* __resolv_context_get_preinit(void)
{
    assert(0);
    return NULL;
}

struct resolv_context* __resolv_context_get_override(struct __res_state* resp)
{
    assert(0);
    return NULL;
}

struct resolv_context* __resolv_context_get(void)
{
    assert(0);
    return NULL;
}

void __resolv_context_put(struct resolv_context* ctx)
{
    assert(0);
}

char* inet_nsap_ntoa(int binlen, const unsigned char* binary, char* ascii)
{
    assert(0);
    return NULL;
}

__thread struct __res_state* __resp = NULL;

void* __libc_reallocarray(void* optr, size_t nmemb, size_t elem_size)
{
    assert(0);
    return NULL;
}
weak_alias(__libc_reallocarray, reallocarray);

void __explicit_bzero_chk(void* __dest, size_t __len, size_t __destlen)
{
    assert(0);
}

int __libc_alloca_cutoff(size_t size)
{
    assert(0);
    return false;
}
