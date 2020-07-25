#ifndef _OEL_ELF_H
#define _OEL_ELF_H

#include <openenclave/bits/types.h>

#define EI_NIDENT 16 /* Size of e_ident[] */

#define AT_NULL		        0
#define AT_IGNORE	        1
#define AT_EXECFD	        2
#define AT_PHDR		        3
#define AT_PHENT	        4
#define AT_PHNUM	        5
#define AT_PAGESZ	        6
#define AT_BASE		        7
#define AT_FLAGS	        8
#define AT_ENTRY	        9
#define AT_NOTELF	        10
#define AT_UID		        11
#define AT_EUID		        12
#define AT_GID		        13
#define AT_EGID		        14
#define AT_PLATFORM	        15
#define AT_HWCAP	        16
#define AT_CLKTCK	        17
#define AT_FPUCW	        18
#define AT_DCACHEBSIZE	        19
#define AT_ICACHEBSIZE	        20
#define AT_UCACHEBSIZE	        21
#define AT_IGNOREPPC	        22
#define	AT_SECURE	        23
#define AT_BASE_PLATFORM        24
#define AT_RANDOM	        25
#define AT_HWCAP2	        26
#define AT_EXECFN	        31
#define AT_SYSINFO	        32
#define AT_SYSINFO_EHDR	        33
#define AT_L1I_CACHESHAPE	34
#define AT_L1D_CACHESHAPE	35
#define AT_L2_CACHESHAPE	36
#define AT_L3_CACHESHAPE	37
#define AT_L1I_CACHESIZE	40
#define AT_L1I_CACHEGEOMETRY	41
#define AT_L1D_CACHESIZE	42
#define AT_L1D_CACHEGEOMETRY	43
#define AT_L2_CACHESIZE		44
#define AT_L2_CACHEGEOMETRY	45
#define AT_L3_CACHESIZE		46
#define AT_L3_CACHEGEOMETRY	47
#define AT_MINSIGSTKSZ		51

#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_SHLIB        5
#define PT_PHDR         6
#define PT_TLS          7
#define PT_NUM          8
#define PT_LOOS         0x60000000
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552
#define PT_LOSUNW       0x6ffffffa
#define PT_SUNWBSS      0x6ffffffa
#define PT_SUNWSTACK    0x6ffffffb
#define PT_HISUNW       0x6fffffff
#define PT_HIOS         0x6fffffff
#define PT_LOPROC       0x70000000
#define PT_HIPROC       0x7fffffff

typedef uint64_t elf64_addr_t;
typedef uint64_t elf64_off_t;
typedef unsigned short elf64_half_t;
typedef unsigned int elf64_word_t;
typedef signed int elf64_sword_t;
typedef uint64_t elf64_xword_t;
typedef int64_t elf64_sxword_t;

typedef struct
{
    unsigned char e_ident[EI_NIDENT];
    elf64_half_t e_type;
    elf64_half_t e_machine;
    elf64_word_t e_version;
    elf64_addr_t e_entry;     /* entry point virtual address */
    elf64_off_t e_phoff;      /* program header table offset */
    elf64_off_t e_shoff;      /* (40) section header table offset */
    elf64_word_t e_flags;     /* process-specific flags */
    elf64_half_t e_ehsize;    /* ELF header size */
    elf64_half_t e_phentsize; /* Program header table entry size */
    elf64_half_t e_phnum;     /* Number of program header table entries */
    elf64_half_t e_shentsize; /* Section header size */
    elf64_half_t e_shnum;     /* Number of section headers */
    elf64_half_t e_shstrndx;  /* Index of the string-table section header */
} elf64_ehdr_t;

typedef struct
{
    elf64_word_t p_type;    /* Type of segment */
    elf64_word_t p_flags;   /* Segment attributes */
    elf64_off_t p_offset;   /* Offset in file */
    elf64_addr_t p_vaddr;   /* Virtual address in memory */
    elf64_addr_t p_paddr;   /* Reserved */
    elf64_xword_t p_filesz; /* Size of segment in file */
    elf64_xword_t p_memsz;  /* Size of segment in memory */
    elf64_xword_t p_align;  /* Alignment of segment */
}
elf64_phdr_t;

const char* elf64_at_string(uint64_t at_value);

const char* elf64_pt_string(uint64_t value);

#endif /* _OEL_ELF_H */
