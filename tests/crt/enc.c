// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
    AT_SYSINFO_EHDR=7ffebe5c8000
    AT_HWCAP=bfebfbff
    AT_PAGESZ=1000
    AT_CLKTCK=64
    AT_PHDR=560102ecb040
    AT_PHENT=38
    AT_PHNUM=9
    AT_BASE=7fd6d9d47000
    AT_FLAGS=0
    AT_ENTRY=560102ecb930
    AT_UID=0
    AT_EUID=0
    AT_GID=0
    AT_EGID=0
    AT_SECURE=0
    AT_RANDOM=7ffebe5aa159
    AT_HWCAP2=0
    AT_EXECFN=7ffebe5abff1
    AT_PLATFORM=7ffebe5aa169
*/

#include <openenclave/enclave.h>
#include "run_t.h"
#include "elf.h"

#define printf oe_host_printf

#define oe_va_list __builtin_va_list
#define oe_va_start __builtin_va_start
#define oe_va_arg __builtin_va_arg
#define oe_va_end __builtin_va_end
#define oe_va_copy __builtin_va_copy

typedef long (*syscall_callback_t)(long n, long params[6]);

int oe_host_printf(const char* fmt, ...);
void* oe_calloc(size_t nmemb, size_t size);
void* oe_memalign(size_t alignment, size_t size);
void oe_free(void* ptr);
size_t oe_strlen(const char *s);
void* memset(void* s, int c, size_t n);
void* memcpy(void* dest, const void* src, size_t n);

static uint64_t _round_up_to_multiple(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

typedef struct
{
    uint64_t a_type;
    union
    {
        uint64_t a_val;
    }
    a_un;
}
auxv_t;

/*
**==============================================================================
** init_stack()
**
** Format:
**
**     [ argc           ]         8
**     [ argv[0]        ]         8
**     [ ...            ]         8
**     [ argv[argc]     ]         8
**     [ envp[0]        ]         8
**     [ ...            ]         8
**     [ envp[envc]     ]         8
**     [ auxv[0]        ]         16
**     [ ...            ]         16
**     [ auxv[auxc]     ]         16
**     [ padding        ]         (padding to 16 byte boundary)
**     [ argv strings   ]         >= 0
**     [ envp strings   ]         >= 0
**     [ padding        ]         (padding to 8 byte boundary)
**     [ end marker     ]         8
**     ...
**     [ stack bottom   ]
**
**==============================================================================
*/
int init_stack(
    int argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    size_t auxc,
    const auxv_t* auxv,
    void* stack, /* 16-byte aligned data */
    size_t stack_size)
{
    int ret = -1;
    size_t argv_offset;
    size_t envp_offset;
    size_t auxv_offset;
    size_t argv_strings_offset;
    size_t envp_strings_offset;
    size_t end_marker_offset;
    size_t end = 0;
    uint8_t* base;

    if (argc <= 0 || !argv || !stack || !stack_size)
        goto done;

    if (auxv == NULL && argc != 0)
        goto done;

    if (envp == NULL && envc != 0)
        goto done;

    /* Calculate the offset of argv[] (skip over argc) */
    argv_offset = sizeof(uint64_t);

    /* calculate offset of envp[] (skip over argv[]) */
    {
        envp_offset = argv_offset;

        /* Skip over argv[] elements (including null terminator) */
        envp_offset += sizeof(const char*) * (argc + 1);
    }

    /* calculate offset of auxv[] (skip over envp[]) */
    {
        auxv_offset = envp_offset;

        /* Skip over envp[] elements (including null terminator) */
        auxv_offset += sizeof(const char*) * (envc + 1);
    }

    /* calculate the offset of the argv[] strings (skip over auxv[]) */
    {
        argv_strings_offset = auxv_offset;

        /* Skip over auxv[] elements (including terminating element) */
        argv_strings_offset += (sizeof(auxv_t)) * (auxc + 1);

        /* Pad to 16-byte boundary */
        argv_strings_offset = _round_up_to_multiple(argv_strings_offset, 16);
    }

    /* calculate the offset of the envp[] strings */
    {
        envp_strings_offset = argv_strings_offset;

        for (int i = 0; i < argc; i++)
            envp_strings_offset += oe_strlen(argv[i]) + 1;
    }

    /* calculate the offset of the end marker */
    {
        end_marker_offset = envp_strings_offset;

        for (size_t i = 0; i < envc; i++)
            end_marker_offset += oe_strlen(envp[i]) + 1;

        end_marker_offset = _round_up_to_multiple(end_marker_offset, 8);
    }

    /* calculate the total size of the data */
    end = end_marker_offset + sizeof(uint64_t);

    if (end > stack_size)
        goto done;

    base = stack;

    /* Initialize argc */
    *((uint64_t*)base) = (uint64_t)argc;

    /* Initialize argv[] */
    {
        char** argv_out = (char**)(base + argv_offset);
        char* p = (char*)(base + argv_strings_offset);

        for (int i = 0; i < argc; i++)
        {
            size_t n = oe_strlen(argv[i]) + 1;
            memcpy(p, argv[i], n);
            argv_out[i] = p;
            p += n;
        }

        /* Initialize the terminator */
        memset(&argv_out[argc], 0, sizeof(auxv_t));
    }

    /* Initialize envp[] */
    {
        char** envp_out = (char**)(base + envp_offset);
        char* p = (char*)(base + envp_strings_offset);

        for (size_t i = 0; i < envc; i++)
        {
            size_t n = oe_strlen(envp[i]) + 1;
            memcpy(p, envp[i], n);
            envp_out[i] = p;
            p += n;
        }

        envp_out[envc] = NULL;
    }

    /* Initialize auxv[] */
    {
        auxv_t* auxv_out = (auxv_t*)(base + auxv_offset);

        for (size_t i = 0; i < auxc; i++)
            auxv_out[i] = auxv[i];

        memset(&auxv_out[auxc], 0, sizeof(auxv_t));
    }

    ret = 0;

done:

    return ret;
}

void dump_stack(void* stack)
{
    int argc = (int)(*(uint64_t*)stack);
    char** argv = (char**)((uint8_t*)stack + sizeof(uint64_t));
    char** envp;
    int envc = 0;
    auxv_t* auxv;

    printf("=== dump_stack()\n");

    printf("argc=%d\n", argc);

    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    envp = (argv + argc + 1);

    for (int i = 0; envp[i]; i++)
    {
        printf("envp[%d]=%s\n", i, envp[i]);
        envc++;
    }

    auxv = (auxv_t*)(envp + envc + 1);

    for (int i = 0; auxv[i].a_type; i++)
    {
        const auxv_t a = auxv[i];
        printf("%s=%lx\n", elf64_at_string(a.a_type), a.a_un.a_val);
    }
}

static void* _make_stack(
    size_t stack_size,
    const void* base,
    const void* ehdr,
    const void* phdr,
    size_t phnum,
    size_t phentsize,
    const void* entry)
{
    void* ret = NULL;
    void* stack = NULL;

    if (!(stack = oe_memalign(16, stack_size)))
        goto done;

    const char* argv[] = { "arg0", "arg1", "arg2", NULL };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    const char* envp[] = { "ENV0=zero", "ENV1=one", "ENV2=two", NULL };
    size_t envc = sizeof(envp) / sizeof(envp[0]) - 1;
    const auxv_t auxv[] =
    {
        {
            .a_type = AT_BASE,
            .a_un.a_val = (uint64_t)base,
        },
        {
            .a_type = AT_SYSINFO_EHDR,
            .a_un.a_val = (uint64_t)ehdr,
        },
        {
            .a_type = AT_PHDR,
            .a_un.a_val = (uint64_t)phdr,
        },
        {
            .a_type = AT_PHNUM,
            .a_un.a_val = (uint64_t)phnum,
        },
        {
            .a_type = AT_PHENT,
            .a_un.a_val = (uint64_t)phentsize,
        },
        {
            .a_type = AT_ENTRY,
            .a_un.a_val = (uint64_t)entry,
        },
        {
            .a_type = AT_PAGESZ,
            .a_un.a_val = 4096,
        },
        {
            .a_type = AT_NULL,
            .a_un.a_val = 0,
        },
    };
    size_t auxc = sizeof(auxv) / sizeof(auxv[0]) - 1;

    if (init_stack(argc, argv, envc, envp, auxc, auxv, stack, stack_size) != 0)
        goto done;

    ret = stack;
    stack = NULL;

done:

    if (stack)
        oe_free(stack);

    return ret;
}

long _syscall(long n, long params[6])
{
    if (n == 1000)
    {
        printf("trace: %s\n", (const char*)params[0]);
    }
    else if (n == 1001)
    {
        printf("trace: %s=%p\n", (const char*)params[0], (void*)params[1]);
    }
    else if (n == 205) /* SYS_set_thread_area */
    {
        void* p = (void*)params[0];
        __asm__ volatile("wrfsbase %0" ::"r"(p));
        return 0;
    }
    else if (n == 218) /* OE_SYS_set_tid_address */
    {
        return 0;
    }
    else
    {
        printf("********** uknown syscall: n=%ld\n", n);
    }
}

#if 0
long musl_syscall_variadic(long n, ...)
{
    oe_va_list ap;
    long params[6];

oel_trace("************ musl_syscall_variadic()");

    oe_va_start(ap, n);
    params[0] = oe_va_arg(ap, long);
    params[1] = oe_va_arg(ap, long);
    params[2] = oe_va_arg(ap, long);
    params[3] = oe_va_arg(ap, long);
    params[4] = oe_va_arg(ap, long);
    params[5] = oe_va_arg(ap, long);
    oe_va_end(ap);

    return musl_syscall(n, params);
}
#endif

static void _enter_crt(void)
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();
    typedef void (*enter_t)(
        void* stack, void* dynv, syscall_callback_t callback);

    enter_t enter = __oe_get_isolated_image_entry_point();
    oe_assert(enter);

    const void* base = __oe_get_isolated_image_base();
    const elf64_ehdr_t* ehdr = base;
    void* stack;
    const size_t stack_size = 256 * 1024;

    /* Extract program-header related info */
    const uint8_t* phdr = (const uint8_t*)base + ehdr->e_phoff;
    size_t phnum = ehdr->e_phnum;
    size_t phentsize = ehdr->e_phentsize;

    if (!(stack = _make_stack(stack_size, base, ehdr, phdr, phnum, phentsize,
        enter)))
    {
        printf("_make_stack() failed\n");
        oe_assert(false);
    }

    dump_stack(stack);

    /* Find the dynamic vector */
    uint64_t* dynv = NULL;
    {
        const uint8_t* p = phdr;

        for (int i = 0; i < phnum; i++)
        {
            const elf64_phdr_t* ph = (const elf64_phdr_t*)p;

            if (ph->p_type == PT_DYNAMIC)
            {
                dynv = (uint64_t*)((uint8_t*)base + ph->p_vaddr);
                break;
            }

            p += phentsize;
        }
    }

    const size_t DYN_CNT = 32;

printf("dynv=%p\n", dynv);
for (size_t i = 0; dynv[i]; i += 2)
{
    if (dynv[i] < DYN_CNT)
        printf("dynv[%lu]=%lx\n", dynv[i], dynv[i+1]);
}

    if (!dynv)
    {
        printf("dynv not found\n");
        oe_assert(false);
    }

    (*enter)(stack, dynv, _syscall);

    oe_free(stack);
}

int run_ecall(void)
{
    _enter_crt();
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
