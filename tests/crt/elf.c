#include "elf.h"

typedef struct _pair
{
    uint8_t at;
    const char* str;
}
pair_t;

static pair_t _pairs[] =
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

static size_t _npairs = sizeof(_pairs) / sizeof(_pairs[0]);

const char* elf64_at_string(uint64_t at_value)
{
    for (size_t i = 0; i < _npairs; i++)
    {
        if (at_value == _pairs[i].at)
            return _pairs[i].str;
    }

    return NULL;
}
