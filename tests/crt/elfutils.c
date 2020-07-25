#include "elfutils.h"
#include <string.h>
#include <stdio.h>

typedef struct _pair
{
    uint64_t num;
    const char* str;
}
pair_t;

static pair_t _at_pairs[] =
{
    { AT_NULL, "AT_NULL" },
    { AT_IGNORE, "AT_IGNORE" },
    { AT_EXECFD, "AT_EXECFD" },
    { AT_PHDR, "AT_PHDR" },
    { AT_PHENT, "AT_PHENT" },
    { AT_PHNUM, "AT_PHNUM" },
    { AT_PAGESZ, "AT_PAGESZ" },
    { AT_BASE, "AT_BASE" },
    { AT_FLAGS, "AT_FLAGS" },
    { AT_ENTRY, "AT_ENTRY" },
    { AT_NOTELF, "AT_NOTELF" },
    { AT_UID, "AT_UID" },
    { AT_EUID, "AT_EUID" },
    { AT_GID, "AT_GID" },
    { AT_EGID, "AT_EGID" },
    { AT_PLATFORM, "AT_PLATFORM" },
    { AT_HWCAP, "AT_HWCAP" },
    { AT_CLKTCK, "AT_CLKTCK" },
    { AT_FPUCW, "AT_FPUCW" },
    { AT_DCACHEBSIZE, "AT_DCACHEBSIZE" },
    { AT_ICACHEBSIZE, "AT_ICACHEBSIZE" },
    { AT_UCACHEBSIZE, "AT_UCACHEBSIZE" },
    { AT_IGNOREPPC, "AT_IGNOREPPC" },
    { AT_SECURE, "AT_SECURE" },
    { AT_BASE_PLATFORM, "AT_BASE_PLATFORM" },
    { AT_RANDOM, "AT_RANDOM" },
    { AT_HWCAP2, "AT_HWCAP2" },
    { AT_EXECFN, "AT_EXECFN" },
    { AT_SYSINFO, "AT_SYSINFO" },
    { AT_SYSINFO_EHDR, "AT_SYSINFO_EHDR" },
    { AT_L1I_CACHESHAPE, "AT_L1I_CACHESHAPE" },
    { AT_L1D_CACHESHAPE, "AT_L1D_CACHESHAPE" },
    { AT_L2_CACHESHAPE, "AT_L2_CACHESHAPE" },
    { AT_L3_CACHESHAPE, "AT_L3_CACHESHAPE" },
    { AT_L1I_CACHESIZE, "AT_L1I_CACHESIZE" },
    { AT_L1I_CACHEGEOMETRY, "AT_L1I_CACHEGEOMETRY" },
    { AT_L1D_CACHESIZE, "AT_L1D_CACHESIZE" },
    { AT_L1D_CACHEGEOMETRY, "AT_L1D_CACHEGEOMETRY" },
    { AT_L2_CACHESIZE, "AT_L2_CACHESIZE" },
    { AT_L2_CACHEGEOMETRY, "AT_L2_CACHEGEOMETRY" },
    { AT_L3_CACHESIZE, "AT_L3_CACHESIZE" },
    { AT_L3_CACHEGEOMETRY, "AT_L3_CACHEGEOMETRY" },
    { AT_MINSIGSTKSZ, "AT_MINSIGSTKSZ" },
};

static size_t _n_at_pairs = sizeof(_at_pairs) / sizeof(_at_pairs[0]);

const char* elf64_at_string(uint64_t value)
{
    for (size_t i = 0; i < _n_at_pairs; i++)
    {
        if (value == _at_pairs[i].num)
            return _at_pairs[i].str;
    }

    return NULL;
}

static pair_t _pt_pairs[] =
{
    { PT_NULL, "PT_NULL" },
    { PT_LOAD, "PT_LOAD" },
    { PT_DYNAMIC, "PT_DYNAMIC" },
    { PT_INTERP, "PT_INTERP" },
    { PT_NOTE, "PT_NOTE" },
    { PT_SHLIB, "PT_SHLIB" },
    { PT_PHDR, "PT_PHDR" },
    { PT_TLS, "PT_TLS" },
    { PT_NUM, "PT_NUM" },
    { PT_LOOS, "PT_LOOS" },
    { PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME" },
    { PT_GNU_STACK, "PT_GNU_STACK" },
    { PT_GNU_RELRO, "PT_GNU_RELRO" },
    { PT_LOSUNW, "PT_LOSUNW" },
    { PT_SUNWBSS, "PT_SUNWBSS" },
    { PT_SUNWSTACK, "PT_SUNWSTACK" },
    { PT_HISUNW, "PT_HISUNW" },
    { PT_HIOS, "PT_HIOS" },
    { PT_LOPROC, "PT_LOPROC" },
    { PT_HIPROC, "PT_HIPROC" },
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
int elf_init_stack(
    int argc,
    const char* argv[],
    size_t envc,
    const char* envp[],
    size_t auxc,
    const Elf64_auxv_t* auxv,
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
        argv_strings_offset += (sizeof(Elf64_auxv_t)) * (auxc + 1);

        /* Pad to 16-byte boundary */
        argv_strings_offset = _round_up_to_multiple(argv_strings_offset, 16);
    }

    /* calculate the offset of the envp[] strings */
    {
        envp_strings_offset = argv_strings_offset;

        for (int i = 0; i < argc; i++)
            envp_strings_offset += strlen(argv[i]) + 1;
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

    base = stack;

    /* Initialize argc */
    *((uint64_t*)base) = (uint64_t)argc;

    /* Initialize argv[] */
    {
        char** argv_out = (char**)(base + argv_offset);
        char* p = (char*)(base + argv_strings_offset);

        for (int i = 0; i < argc; i++)
        {
            size_t n = strlen(argv[i]) + 1;
            memcpy(p, argv[i], n);
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

    ret = 0;

done:

    return ret;
}

void elf_dump_stack(void* stack)
{
    int argc = (int)(*(uint64_t*)stack);
    char** argv = (char**)((uint8_t*)stack + sizeof(uint64_t));
    char** envp;
    int envc = 0;
    Elf64_auxv_t* auxv;

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

    auxv = (Elf64_auxv_t*)(envp + envc + 1);

    for (int i = 0; auxv[i].a_type; i++)
    {
        const Elf64_auxv_t a = auxv[i];
        printf("%s=%lx\n", elf64_at_string(a.a_type), a.a_un.a_val);
    }
}
