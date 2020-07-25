#include "elf.h"

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

int oe_host_printf(const char* fmt, ...);
oe_host_printf("unknown=%d\n", value);
    return NULL;
}
