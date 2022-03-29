// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <myst/args.h>
#include <myst/atexit.h>
#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/exec.h>
#include <myst/file.h>
#include <myst/fsgs.h>
#include <myst/kernel.h>
#include <myst/libc.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/paths.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/procfs.h>
#include <myst/reloc.h>
#include <myst/round.h>
#include <myst/setjmp.h>
#include <myst/sharedmem.h>
#include <myst/signal.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
#include <myst/tcall.h>
#include <myst/thread.h>

#define GUARD 0x4f

#define GLIBC_THREAD_STACK_SIZE_MIN 1048576 /* 1mb */

#define THREAD_STACK_SIZE_WARNING \
    "\n\
    The thread stack size may be too small for the given program interpreter\n\
    (link loader), which could result in stack overflows. Consider changing\n\
    the thread stack size to at least %u bytes, using the --thread-stack-size\n\
    option or the ThreadStackSize configuration setting.\n\
    [interpreter=%s]\n\
    [program=%s]\n"

typedef struct _pair
{
    uint64_t num;
    const char* str;
} pair_t;

static pair_t _at_pairs[] = {
    {AT_NULL, "AT_NULL"},
    {AT_IGNORE, "AT_IGNORE"},
    {AT_EXECFD, "AT_EXECFD"},
    {AT_PHDR, "AT_PHDR"},
    {AT_PHENT, "AT_PHENT"},
    {AT_PHNUM, "AT_PHNUM"},
    {AT_PAGESZ, "AT_PAGESZ"},
    {AT_BASE, "AT_BASE"},
    {AT_FLAGS, "AT_FLAGS"},
    {AT_ENTRY, "AT_ENTRY"},
    {AT_NOTELF, "AT_NOTELF"},
    {AT_UID, "AT_UID"},
    {AT_EUID, "AT_EUID"},
    {AT_GID, "AT_GID"},
    {AT_EGID, "AT_EGID"},
    {AT_PLATFORM, "AT_PLATFORM"},
    {AT_HWCAP, "AT_HWCAP"},
    {AT_CLKTCK, "AT_CLKTCK"},
    {AT_FPUCW, "AT_FPUCW"},
    {AT_DCACHEBSIZE, "AT_DCACHEBSIZE"},
    {AT_ICACHEBSIZE, "AT_ICACHEBSIZE"},
    {AT_UCACHEBSIZE, "AT_UCACHEBSIZE"},
    {AT_IGNOREPPC, "AT_IGNOREPPC"},
    {AT_SECURE, "AT_SECURE"},
    {AT_BASE_PLATFORM, "AT_BASE_PLATFORM"},
    {AT_RANDOM, "AT_RANDOM"},
    {AT_HWCAP2, "AT_HWCAP2"},
    {AT_EXECFN, "AT_EXECFN"},
    {AT_SYSINFO, "AT_SYSINFO"},
    {AT_SYSINFO_EHDR, "AT_SYSINFO_EHDR"},
    {AT_L1I_CACHESHAPE, "AT_L1I_CACHESHAPE"},
    {AT_L1D_CACHESHAPE, "AT_L1D_CACHESHAPE"},
    {AT_L2_CACHESHAPE, "AT_L2_CACHESHAPE"},
    {AT_L3_CACHESHAPE, "AT_L3_CACHESHAPE"},
    {AT_L1I_CACHESIZE, "AT_L1I_CACHESIZE"},
    {AT_L1I_CACHEGEOMETRY, "AT_L1I_CACHEGEOMETRY"},
    {AT_L1D_CACHESIZE, "AT_L1D_CACHESIZE"},
    {AT_L1D_CACHEGEOMETRY, "AT_L1D_CACHEGEOMETRY"},
    {AT_L2_CACHESIZE, "AT_L2_CACHESIZE"},
    {AT_L2_CACHEGEOMETRY, "AT_L2_CACHEGEOMETRY"},
    {AT_L3_CACHESIZE, "AT_L3_CACHESIZE"},
    {AT_L3_CACHEGEOMETRY, "AT_L3_CACHEGEOMETRY"},
    {AT_MINSIGSTKSZ, "AT_MINSIGSTKSZ"},
};

static size_t _n_at_pairs = sizeof(_at_pairs) / sizeof(_at_pairs[0]);

static size_t _thread_stack_size = 0;

const char* elf64_at_string(uint64_t value)
{
    for (size_t i = 0; i < _n_at_pairs; i++)
    {
        if (value == _at_pairs[i].num)
            return _at_pairs[i].str;
    }

    return NULL;
}

static pair_t _pt_pairs[] = {
    {PT_NULL, "PT_NULL"},
    {PT_LOAD, "PT_LOAD"},
    {PT_DYNAMIC, "PT_DYNAMIC"},
    {PT_INTERP, "PT_INTERP"},
    {PT_NOTE, "PT_NOTE"},
    {PT_SHLIB, "PT_SHLIB"},
    {PT_PHDR, "PT_PHDR"},
    {PT_TLS, "PT_TLS"},
    {PT_NUM, "PT_NUM"},
    {PT_LOOS, "PT_LOOS"},
    {PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME"},
    {PT_GNU_STACK, "PT_GNU_STACK"},
    {PT_GNU_RELRO, "PT_GNU_RELRO"},
    {PT_LOSUNW, "PT_LOSUNW"},
    {PT_SUNWBSS, "PT_SUNWBSS"},
    {PT_SUNWSTACK, "PT_SUNWSTACK"},
    {PT_HISUNW, "PT_HISUNW"},
    {PT_HIOS, "PT_HIOS"},
    {PT_LOPROC, "PT_LOPROC"},
    {PT_HIPROC, "PT_HIPROC"},
};

static size_t _n_pt_pairs = sizeof(_pt_pairs) / sizeof(_pt_pairs[0]);

const char* elf64_pt_string(uint64_t value)
{
    for (size_t i = 0; i < _n_pt_pairs; i++)
    {
        if (value == _pt_pairs[i].num)
            return _pt_pairs[i].str;
    }

    return NULL;
}

static uint64_t _round_up_to_multiple(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

/*
**==============================================================================
** elf_init_stack()
**
** Layout of stack:
**
**     <------- stack size --------->
**     [guard][stack][vectors][guard]
**     ^             ^
**     stack         sp
**
** Layout of vectors:
**
**     [ argc           ]         8 (stack pointer)
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
**
**==============================================================================
*/
int elf_init_stack(
    size_t argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    size_t auxc,
    const Elf64_auxv_t* auxv,
    void* stack, /* 16-byte aligned data */
    size_t stack_size,
    void** sp_out)
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
    void* sp;
    const char arg0[] = "ldso";

    if (sp_out)
        *sp_out = NULL;

    if (argc <= 0 || !argv || !stack || !stack_size || !sp_out)
        goto done;

    if (auxv == NULL && auxc != 0)
        goto done;

    if (envp == NULL && envc != 0)
        goto done;

    /* make room for injecting the dummy arg0 */
    argc++;

    /* The stack must be a multiple of the page size */
    if (stack_size % PAGE_SIZE)
        goto done;

    /* The stack must be algined on a page boundary */
    if ((uint64_t)stack % PAGE_SIZE)
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
        argv_strings_offset += (sizeof(Elf64_auxv_t)) * (auxc + 1);

        /* Pad to 16-byte boundary */
        argv_strings_offset = _round_up_to_multiple(argv_strings_offset, 16);
    }

    /* calculate the offset of the envp[] strings */
    {
        envp_strings_offset = argv_strings_offset;

        for (size_t i = 0; i < argc; i++)
        {
            const char* arg = (i == 0) ? arg0 : argv[i - 1];
            envp_strings_offset += strlen(arg) + 1;
        }
    }

    /* calculate the offset of the end marker */
    {
        end_marker_offset = envp_strings_offset;

        for (size_t i = 0; i < envc; i++)
            end_marker_offset += strlen(envp[i]) + 1;

        end_marker_offset = _round_up_to_multiple(end_marker_offset, 8);
    }

    /* calculate the total size of the data */
    end = end_marker_offset + sizeof(uint64_t);

    if (end > stack_size)
        goto done;

    /* Make sure stack is big enough for all elements */
    {
        size_t required_stack_size = 0;

        /* Count the first guard page */
        required_stack_size += PAGE_SIZE;

        /* Count at least 4 pages for stack */
        required_stack_size += 4 * PAGE_SIZE;

        /* Count the vectors space (argv, envp, auxv) */
        required_stack_size += end;

        /* Count the final guard page */
        required_stack_size += PAGE_SIZE;

        if (required_stack_size > stack_size)
            goto done;
    }

    /* Calculate the position of the stack pointer */
    {
        size_t sp_offset = stack_size;

        /* Leave room for a guard page at the very end */
        sp_offset -= PAGE_SIZE;

        /* Leave room for vectors (argv, envp, auxv) */
        sp_offset -= end;

        /* Round down to a multiple of the page size */
        sp_offset = sp_offset & ~((size_t)PAGE_SIZE - 1);

        sp = (uint8_t*)stack + sp_offset;
    }

    base = sp;

    /* Initialize argc */
    *((uint64_t*)base) = (uint64_t)argc;

    /* Initialize argv[] */
    {
        char** argv_out = (char**)(base + argv_offset);
        char* p = (char*)(base + argv_strings_offset);

        for (size_t i = 0; i < argc; i++)
        {
            const char* arg = (i == 0) ? arg0 : argv[i - 1];
            size_t n = strlen(arg) + 1;
            memcpy(p, arg, n);
            argv_out[i] = p;
            p += n;
        }

        /* Initialize the terminator */
        memset(&argv_out[argc], 0, sizeof(Elf64_auxv_t));
    }

    /* Initialize envp[] */
    {
        char** envp_out = (char**)(base + envp_offset);
        char* p = (char*)(base + envp_strings_offset);

        for (size_t i = 0; i < envc; i++)
        {
            size_t n = strlen(envp[i]) + 1;
            memcpy(p, envp[i], n);
            envp_out[i] = p;
            p += n;
        }

        envp_out[envc] = NULL;
    }

    /* Initialize auxv[] */
    {
        Elf64_auxv_t* auxv_out = (Elf64_auxv_t*)(base + auxv_offset);

        for (size_t i = 0; i < auxc; i++)
            auxv_out[i] = auxv[i];

        memset(&auxv_out[auxc], 0, sizeof(Elf64_auxv_t));
    }

    /* Make the enclosing guard pages inaccessible */
    ECHECK(myst_mprotect(stack, PAGE_SIZE, PROT_NONE));
    ECHECK(myst_mprotect(
        (uint8_t*)stack + stack_size - PAGE_SIZE, PAGE_SIZE, PROT_NONE));

    *sp_out = sp;

    ret = 0;

done:

    return ret;
}

static void _dump_bytes(const void* p_, size_t n)
{
    const uint8_t* p = (const uint8_t*)p_;
    while (n--)
    {
        uint8_t c = *p++;

        if (c >= ' ' && c <= '~')
            printf("%c", c);
        else
            printf("<%02x>", c);
    }

    printf("\n");
}

void myst_dump_stack(void* stack)
{
    int argc = (int)(*(uint64_t*)stack);
    char** argv = (char**)((uint8_t*)stack + sizeof(uint64_t));
    char** envp;
    int envc = 0;
    Elf64_auxv_t* auxv;
    const Elf64_auxv_t* auxv_end = NULL;

    printf("=== dump_stack(%lX)\n", (unsigned long)stack);

    printf("stack=%lx\n", (uint64_t)stack);

#if 0
    printf("prev=%lx\n", *((uint64_t*)stack - 1));
#endif

    printf("argc=%d\n", argc);

    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s [%lX]\n", i, argv[i], (uint64_t)argv[i]);

    envp = (argv + argc + 1);

    for (int i = 0; envp[i]; i++)
    {
        printf("envp[%d]=%s [%lX]\n", i, envp[i], (uint64_t)envp[i]);
        envc++;
    }

    /* Dump the argv strings */

    auxv = (Elf64_auxv_t*)(envp + envc + 1);

    for (int i = 0; auxv[i].a_type; i++)
    {
        const Elf64_auxv_t a = auxv[i];
        printf("%s=%lX\n", elf64_at_string(a.a_type), a.a_un.a_val);
        auxv_end = &auxv[i];
    }

    auxv_end++;

    _dump_bytes(auxv_end, 80);
}

int _test_header(const Elf64_Ehdr* ehdr)
{
    if (!ehdr)
        return -1;

    if (ehdr->e_ident[EI_MAG0] != 0x7f)
        return -1;

    if (ehdr->e_ident[EI_MAG1] != 'E')
        return -1;

    if (ehdr->e_ident[EI_MAG2] != 'L')
        return -1;

    if (ehdr->e_ident[EI_MAG3] != 'F')
        return -1;

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return -1;

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;

    if (ehdr->e_machine != EM_X86_64)
        return -1;

    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr))
        return -1;

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return -1;

    if (ehdr->e_shentsize != sizeof(Elf64_Shdr))
        return -1;

    /* If there is no section header table, then the index should be 0. */
    if (ehdr->e_shnum == 0 && ehdr->e_shstrndx != 0)
        return -1;

    /* If there is a section header table, then the index shouldn't overrun. */
    if (ehdr->e_shnum > 0 && ehdr->e_shstrndx >= ehdr->e_shnum)
        return -1;

    return 0;
}

int myst_dump_ehdr(const void* ehdr)
{
    const Elf64_Ehdr* h = (const Elf64_Ehdr*)ehdr;

    if (!h || _test_header(h) != 0)
        return -1;

    printf("=== elf64_ehdr_t(%lX)\n", (unsigned long)h);

    /* Print e_ident[] */
    printf("e_ident[EI_MAG0]=%02x\n", h->e_ident[EI_MAG0]);
    printf("e_ident[EI_MAG1]=%c\n", h->e_ident[EI_MAG1]);
    printf("e_ident[EI_MAG2]=%c\n", h->e_ident[EI_MAG2]);
    printf("e_ident[EI_MAG3]=%c\n", h->e_ident[EI_MAG3]);

    switch (h->e_ident[EI_CLASS])
    {
        case ELFCLASSNONE:
            printf("e_ident[EI_CLASS]=ELFCLASSNONE\n");
            break;
        case ELFCLASS32:
            printf("e_ident[EI_CLASS]=ELFCLASS32\n");
            break;
        case ELFCLASS64:
            printf("e_ident[EI_CLASS]=ELFCLASS64\n");
            break;
        default:
            printf("e_ident[EI_CLASS]=%02x\n", h->e_ident[EI_CLASS]);
            break;
    }

    switch (h->e_ident[EI_DATA])
    {
        case ELFDATANONE:
            printf("e_ident[EI_DATA]=ELFDATANONE\n");
            break;
        case ELFDATA2LSB:
            printf("e_ident[EI_DATA]=ELFDATA2LSB\n");
            break;
        case ELFDATA2MSB:
            printf("e_ident[EI_DATA]=ELFDATA2MSB\n");
            break;
        default:
            printf("e_ident[EI_DATA]=%02x\n", h->e_ident[EI_DATA]);
            break;
    }

    printf("e_ident[EI_VERSION]=%02x\n", h->e_ident[EI_VERSION]);
    printf("e_ident[EI_PAD]=%02x\n", h->e_ident[EI_PAD]);

    switch (h->e_type)
    {
        case ET_NONE:
            printf("e_type=ET_NONE\n");
            break;
        case ET_REL:
            printf("e_type=ET_REL\n");
            break;
        case ET_EXEC:
            printf("e_type=ET_EXEC\n");
            break;
        case ET_DYN:
            printf("e_type=ET_DYN\n");
            break;
        case ET_CORE:
            printf("e_type=ET_CORE\n");
            break;
        case ET_LOPROC:
            printf("e_type=ET_LOPROC\n");
            break;
        case ET_HIPROC:
            printf("e_type=ET_HIPROC\n");
            break;
        default:
            printf("e_type=%02x\n", h->e_type);
            break;
    }

    switch (h->e_machine)
    {
        case EM_NONE:
            printf("e_machine=EM_NONE\n");
            break;
        case EM_M32:
            printf("e_machine=EM_M32\n");
            break;
        case EM_SPARC:
            printf("e_machine=EM_SPARC\n");
            break;
        case EM_386:
            printf("e_machine=EM_386\n");
            break;
        case EM_68K:
            printf("e_machine=EM_68K\n");
            break;
        case EM_88K:
            printf("e_machine=EM_88K\n");
            break;
        case EM_860:
            printf("e_machine=EM_860\n");
            break;
        case EM_MIPS:
            printf("e_machine=EM_MIPS\n");
            break;
        case EM_X86_64:
            printf("e_machine=EM_X86_64\n");
            break;
        default:
            printf("e_machine=%u\n", h->e_machine);
            break;
    }

    printf("e_version=%u\n", h->e_version);
    printf("e_entry=%lX\n", h->e_entry);
    printf("e_phoff=%lu\n", h->e_phoff);
    printf("e_shoff=%lu\n", h->e_shoff);
    printf("e_flags=%u\n", h->e_flags);
    printf("e_ehsize=%u\n", h->e_ehsize);
    printf("e_phentsize=%u\n", h->e_phentsize);
    printf("e_phnum=%u\n", h->e_phnum);
    printf("e_shentsize=%u\n", h->e_shentsize);
    printf("e_shnum=%u\n", h->e_shnum);
    printf("e_shstrndx=%u\n", h->e_shstrndx);
    printf("\n");

    return 0;
}

int elf_check_stack(const void* stack, size_t stack_size)
{
    int ret = -1;

    if (!stack || !stack_size)
        goto done;

    if ((uint64_t)stack % PAGE_SIZE)
        goto done;

    if (stack_size % PAGE_SIZE)
        goto done;

    if (stack_size < 2 * PAGE_SIZE)
        goto done;

    ret = 0;

done:
    return ret;
}

void* elf_make_stack(
    size_t argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    size_t stack_size,
    const void* base,
    const void* phdr,
    size_t phnum,
    size_t phentsize,
    const void* entry,
    void** sp)
{
    void* ret = NULL;
    void* stack = NULL;

    if (sp)
        *sp = NULL;

    /* Assume that the stack is aligned on a page boundary */
    myst_assume((stack_size % PAGE_SIZE) == 0);

    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

    stack = (void*)myst_mmap(NULL, stack_size, prot, flags, -1, 0);
    if ((long)stack < 0)
        goto done;

    memset(stack, 0, stack_size);

    /*  Example:
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
    const Elf64_auxv_t auxv[] = {
        {
            .a_type = AT_BASE,
            .a_un.a_val = (uint64_t)base,
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
            .a_un.a_val = PAGE_SIZE,
        },
        {
            .a_type = AT_NULL,
            .a_un.a_val = 0,
        },
    };
    size_t auxc = sizeof(auxv) / sizeof(auxv[0]) - 1;

    if (elf_init_stack(
            argc, argv, envc, envp, auxc, auxv, stack, stack_size, sp) != 0)
    {
        goto done;
    }

    ret = stack;
    stack = NULL;

done:

    if (stack)
        myst_munmap(stack, stack_size);

    return ret;
}

typedef long (*syscall_callback_t)(long n, long params[6]);

typedef void (*enter_t)(
    void* stack,
    void* dynv,
    syscall_callback_t callback,
    myst_crt_args_t* args);

typedef struct entry_args
{
    enter_t enter;
    void* stack;
    uint64_t* dynv;
    long (*syscall)(long n, long params[6]);
    int (*liboc_libc_init)(libc_t* libc, FILE* const stderr_file);
} entry_args_t;

static long _add_crt_symbols(const void* text, size_t text_size)
{
    long ret = 0;
    long params[6] = {0};

    params[0] = (long)NULL;
    params[1] = 0;
    params[2] = (long)text;
    params[3] = (long)text_size;

    ECHECK(myst_tcall(MYST_TCALL_ADD_SYMBOL_FILE, params));

done:

    return ret;
}

static int _get_shell_interpreter(
    char* hashbang_buff,
    size_t hashbang_buff_length,
    ssize_t num_bytes_read,
    myst_args_t* new_argv)
{
    int ret = 0;
    char* start_string = NULL;
    char* cursor = hashbang_buff + 2; // starts after hashbang

    do
    {
        if (cursor == (hashbang_buff + hashbang_buff_length - 1))
        {
            /* We have reached the end of the buffer (with space for a null
             * terminator) */
            /* ATTN: support longer hashbang string */
            myst_panic("script hashbang path is too long");
            ERAISE(-ENAMETOOLONG);
        }
        else if (cursor - hashbang_buff >= num_bytes_read)
        {
            /* got to end of read buffer */
            if (start_string)
            {
                cursor[0] = '\0';
                if (myst_args_append1(new_argv, start_string) != 0)
                    ERAISE(-ENOMEM);
            }
            break;
        }
        else if (start_string != NULL && cursor[0] == '\n')
        {
            /* end of line with a pointer to string. Add string to args and
             * break out */
            cursor[0] = '\0';
            if (myst_args_append1(new_argv, start_string) != 0)
                ERAISE(-ENOMEM);
            break;
        }
        else if (start_string == NULL && cursor[0] == '\n')
        {
            /* We are parsing white space and hit end of line. Nothing to do
             * but exit */
            break;
        }
        else if (
            start_string != NULL && (cursor[0] == ' ' || cursor[0] == '\t'))
        {
            /* have the start of a string and hit end of string. Add it and
             * continue  */
            cursor[0] = '\0';
            if (myst_args_append1(new_argv, start_string) != 0)
                ERAISE(-ENOMEM);
            start_string = NULL;
        }
        else if (start_string == NULL && cursor[0] != ' ' && cursor[0] != '\t')
        {
            /* Start of string so remember so we can add it later */
            start_string = cursor;
        }
        cursor++;

    } while (1);

    if (new_argv->size == 0)
    {
        /* We dont have even one string after the hashbang */
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

/* Get the program interpreter from the PT_INTERP program header */
static int _get_prog_interp(const char* path, char** name_out)
{
    int ret = 0;
    int fd = -1;
    Elf64_Ehdr* ehdr = NULL;
    Elf64_Phdr phdr;
    bool found = false;
    char* name = NULL;

    *name_out = NULL;

    /* Open the (potential) executable file */
    ECHECK(fd = myst_syscall_open(path, O_RDONLY, 0));

    /* Read the ELF header */
    {
        if (!(ehdr = malloc(sizeof(Elf64_Ehdr))))
            ERAISE(-ENOMEM);

        ECHECK(myst_syscall_read(fd, ehdr, sizeof(Elf64_Ehdr)));
    }

    /* Verify the ELF header */
    if (_test_header(ehdr) != 0)
        ERAISE(-ENOENT);

    /* Seek to location of the program header table file offset */
    ECHECK(myst_syscall_lseek(fd, ehdr->e_phoff, SEEK_SET));

    /* Find the program header for the PT_INTERP */
    for (size_t i = 0; i < ehdr->e_phnum; i++)
    {
        ssize_t n = myst_syscall_read(fd, &phdr, sizeof(Elf64_Phdr));
        ECHECK(n);

        if (n != sizeof(Elf64_Phdr))
            ERAISE(-EIO);

        if (phdr.p_type == PT_INTERP)
        {
            found = true;
            break;
        }
    }
    if (!found)
        ERAISE(-ENOENT);

    /* If the size of the PT_INTERP segment is unreasonably long */
    if (phdr.p_filesz >= PATH_MAX)
        ERAISE(-ENAMETOOLONG);

    /* Seek to location of PT_INTERP segment */
    ECHECK(myst_syscall_lseek(fd, phdr.p_offset, SEEK_SET));

    /* Allocate memory for the program interpreter name */
    if (!(name = malloc(phdr.p_filesz + 1)))
        ERAISE(-ENOMEM);

    /* Read the program interpreter name */
    {
        ssize_t n = myst_syscall_read(fd, name, phdr.p_filesz);
        ECHECK(n);

        if ((size_t)n != phdr.p_filesz)
            ERAISE(-EIO);

        name[phdr.p_filesz] = '\0';
    }

    *name_out = name;
    name = NULL;

done:

    if (name)
        free(name);

    if (fd >= 0)
        myst_syscall_close(fd);

    if (ehdr)
        free(ehdr);

    return ret;
}

int myst_exec(
    myst_thread_t* thread,
    const void* crt_data_in,
    size_t crt_size,
    const void* crt_reloc_data,
    size_t crt_reloc_size,
    size_t argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    myst_crt_args_t* crt_args,
    size_t thread_stack_size,
    void (*callback)(void*), /* used to release caller-allocated parameters */
    void* callback_arg)
{
    int ret = 0;
    void* stack = NULL;
    void* sp = NULL;
    void* crt_data = NULL;
    const Elf64_Ehdr* ehdr = NULL;
    Elf64_Phdr* phdr = NULL;
    uint64_t* dynv = NULL;
    enter_t enter;
    char* envp_buf[] = {NULL};
    myst_process_t* process = NULL;
    char* hashbang_buff = NULL;
    size_t hashbang_buff_length = 0;
    long hashbang_file = -1;
    myst_args_t new_argv;
    size_t num_bytes_read;
    char* prog_interp = NULL;
    size_t actual_thread_stack_size = thread_stack_size;

    if (thread_stack_size)
        _thread_stack_size = thread_stack_size;

    if (myst_args_init(&new_argv) != 0)
        ERAISE(ENOMEM);

    if (!envp)
        envp = (const char**)envp_buf;

    if (!thread || !crt_data_in || !crt_size || !argv)
        ERAISE(-EINVAL);

    /* fail if image does not have a valid ELF header */
    if (_test_header(crt_data_in) != 0)
        ERAISE(-EINVAL);

    /* fail if the CRT size is not a multiple of the page size */
    if ((crt_size % PAGE_SIZE) != 0)
        ERAISE(-EINVAL);

    process = thread->process;

    /* reset sigactions */
    myst_signal_init(process);

    /* allocate and zero-fill the new CRT image */
    {
        const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
        const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

        crt_data = (void*)myst_mmap(NULL, crt_size, prot, flags, -1, 0);

        if ((long)crt_data < 0)
            ERAISE(-ENOMEM);
    }

    /* Copy over the loadable segments */
    {
        const Elf64_Ehdr* eh = crt_data_in;
        const uint8_t* p = (const uint8_t*)crt_data_in + eh->e_phoff;
        size_t ending_vaddr = 0;

        for (size_t i = 0; i < eh->e_phnum; i++)
        {
            const Elf64_Phdr* ph = (const Elf64_Phdr*)p;

            if (ph->p_type == PT_LOAD)
            {
                void* dest = (uint8_t*)crt_data + ph->p_vaddr;
                const void* src = (const uint8_t*)crt_data_in + ph->p_vaddr;
                size_t gap_size;

                if (ph->p_vaddr < ending_vaddr)
                    myst_panic("unsorted segments");

                memcpy(dest, src, ph->p_memsz);

                /* unmap any gap between this segment and the last */
                if ((gap_size = ph->p_vaddr - ending_vaddr))
                {
                    uint8_t* gap = (uint8_t*)crt_data + ending_vaddr;

                    /* round gap up to page size */
                    const uint64_t m = PAGE_SIZE;
                    ECHECK(myst_round_up((uint64_t)gap, m, (uint64_t*)&gap));

                    /* round the gap size down to the page size */
                    gap_size = myst_round_down_to_page_size(gap_size);

#if 0
                    // ATTN-8185D7BF: prevents CRT region from being released
                    ECHECK(myst_munmap(gap, gap_size));
#endif
                }

                /* remember the end of this segment for the next pass */
                ending_vaddr = ph->p_vaddr + ph->p_memsz;
            }

            p += eh->e_phentsize;
        }
    }

    /* Find the dynamic vector: dynv */
    {
        ehdr = crt_data;
        const uint8_t* p = (const uint8_t*)crt_data + ehdr->e_phoff;

        for (size_t i = 0; i < ehdr->e_phnum; i++)
        {
            const Elf64_Phdr* ph = (const Elf64_Phdr*)p;

            if (ph->p_type == PT_DYNAMIC)
            {
                dynv = (uint64_t*)((uint8_t*)crt_data + ph->p_vaddr);
                break;
            }

            p += ehdr->e_phentsize;
        }
    }

    /* apply relocations to the new CRT data */
    if (myst_apply_relocations(
            crt_data, crt_size, crt_reloc_data, crt_reloc_size) != 0)
    {
        ERAISE(-EINVAL);
    }

    /* save the phdr */
    phdr = (Elf64_Phdr*)((const uint8_t*)crt_data + ehdr->e_phoff);

    /* Patch the PT_GNU_STACK entry */
    {
        ehdr = crt_data;
        for (size_t i = 0; i < ehdr->e_phnum; i++)
        {
            if (phdr[i].p_type == PT_GNU_STACK)
            {
                if (_thread_stack_size > phdr[i].p_memsz)
                    phdr[i].p_memsz = _thread_stack_size;

                actual_thread_stack_size = phdr[i].p_memsz;
            }
        }
    }

    /* save the entry point */
    enter = (enter_t)((uint8_t*)crt_data + ehdr->e_entry);

    if (!dynv)
        ERAISE(-EINVAL);

    /* Now we need to determine if this has a #! at the start of the file.
     * Lets start with allocating a buffer that is big enough for a file path,
     * plus hashbang and null terminator. We may need to reallocate if it is not
     * long enough.
     */
    hashbang_buff_length = PATH_MAX + 3 + 1;
    hashbang_buff = malloc(hashbang_buff_length);
    if (hashbang_buff == NULL)
        ERAISE(-ENOMEM);

    hashbang_file = myst_syscall_open(argv[0], O_RDONLY, 0);
    ECHECK(hashbang_file);

    ECHECK(
        num_bytes_read = myst_syscall_read(
            hashbang_file, hashbang_buff, hashbang_buff_length));

    if ((num_bytes_read >= 2) && (strncmp(hashbang_buff, "#!", 2) == 0))
    {
        ECHECK(_get_shell_interpreter(
            hashbang_buff, hashbang_buff_length, num_bytes_read, &new_argv));
    }
    else
    {
        ECHECK(_get_prog_interp(argv[0], &prog_interp));
    }

    /* Check that the stack is big enough for the program interpreter */
    if (prog_interp && strstr(prog_interp, "ld-linux") &&
        actual_thread_stack_size < GLIBC_THREAD_STACK_SIZE_MIN)
    {
        MYST_WLOG(
            THREAD_STACK_SIZE_WARNING,
            GLIBC_THREAD_STACK_SIZE_MIN,
            prog_interp,
            argv[0]);
    }

    if (myst_args_append(&new_argv, argv, argc) != 0)
        ERAISE(-ENOMEM);

    myst_syscall_close(hashbang_file);
    hashbang_file = -1;

    if (!(stack = elf_make_stack(
              new_argv.size,
              new_argv.data,
              envc,
              envp,
              __myst_kernel_args.main_stack_size,
              crt_data,
              phdr,
              ehdr->e_phnum,
              ehdr->e_phentsize,
              enter,
              &sp)))
    {
        ERAISE(-ENOMEM);
    }

    assert(elf_check_stack(stack, __myst_kernel_args.main_stack_size) == 0);

    /* create "/proc/<pid>/exe" which is a link to the program executable */
    if (procfs_setup_exe_link(new_argv.data[0], myst_getpid()) != 0)
        ERAISE(-EIO);

    myst_args_release(&new_argv);
    free(hashbang_buff);
    hashbang_buff = NULL;

    /* if this is a nested exec, then release previous process mappings
     * assicoated to the pid */
    myst_release_process_mappings(process->pid);

    /* set pid to the newly allocated crt data (now part of the process
     * mappings) */
    if (myst_mman_pids_set(crt_data, crt_size, process->pid) != 0)
        myst_panic("myst_mman_pids_set()");

    /* set pid to the newly allocated stack (now part of the process
     * mappings) */
    if (myst_mman_pids_set(
            stack, __myst_kernel_args.main_stack_size, process->pid) != 0)
        myst_panic("myst_mman_pids_set()");

    /* used by myst_syscall_get_process_thread_stack */
    process->exec_stack = stack;
    process->exec_stack_size = __myst_kernel_args.main_stack_size;
#ifdef MYST_THREAD_KEEP_CRT_PTR
    process->exec_crt_data = crt_data;
    process->exec_crt_size = crt_size;
#endif

    /* always clear the signal delivery altstack on exec */
    myst_clear_signal_delivery_altstack(thread);

    /* close file descriptors with FD_CLOEXEC flag */
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fdtable_cloexec(fdtable);
    }

    /* register the new CRT symbols with the debugger */
    if (__myst_kernel_args.debug_symbols)
        ECHECK(_add_crt_symbols(crt_data, crt_size));

    /* remove the thread clone flag CLONE_VFORK flag as this is used to
     * determine if we do CRT cleanup. As we are re-initializing the CRT it is
     * safe to re-enable the cleanup.
     * At the same time we may need to wake the parent processes thread that
     * launched us in the case we were created in the fork/exec wait mode. */
    if (process->is_pseudo_fork_process)
    {
        myst_fork_exec_futex_wake(
            process->vfork_parent_pid, process->vfork_parent_tid);

        process->is_pseudo_fork_process = false;
        process->vfork_parent_tid = 0;
        process->vfork_parent_pid = 0;
    }
    process->num_pseudo_children--;

    /* Unmap inherited POSIX shm mappings */
    myst_shmem_handle_release_mappings(process->pid);

    /* invoke the caller's callback here */
    if (callback)
        (*callback)(callback_arg);

    /* enter the C-runtime on the target thread descriptor */
    (*enter)(sp, dynv, myst_syscall, crt_args);

    /* unreachable */

    process->exec_stack = NULL;
    process->exec_stack_size = 0;
#ifdef MYST_THREAD_KEEP_CRT_PTR
    process->exec_crt_data = NULL;
    process->exec_crt_size = 0;
#endif
    ERAISE(-ENOEXEC);

done:

    if (stack)
        myst_munmap(stack, __myst_kernel_args.main_stack_size);

    if (crt_data)
        myst_munmap(crt_data, crt_size);

    if (hashbang_buff)
        free(hashbang_buff);

    if (hashbang_file != -1)
        myst_syscall_close(hashbang_file);

    myst_args_release(&new_argv);

    if (prog_interp)
        free(prog_interp);

    return ret;
}
