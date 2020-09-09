// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _LIBOS_ELF_H
#define _LIBOS_ELF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
**==============================================================================
**
** ELF parser:
**
**==============================================================================
*/

/* elf_ehdr_t.e_ident */
#define EI_MAG0 0    /* File identification */
#define EI_MAG1 1    /* File identification */
#define EI_MAG2 2    /* File identification */
#define EI_MAG3 3    /* File identification */
#define EI_CLASS 4   /* File class */
#define EI_DATA 5    /* Data encoding */
#define EI_VERSION 6 /* File version */
#define EI_PAD 7     /* Start of padding bytes */
#define EI_NIDENT 16 /* Size of e_ident[] */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASSNONE 0 /* Invalid class */
#define ELFCLASS32 1   /* 32-bit objects e_ident[EI_CLASS] */
#define ELFCLASS64 2   /* 64-bit objects */
#define ELFDATANONE 0  /* Invalid data encoding */
#define ELFDATA2LSB 1  /* See below */
#define ELFDATA2MSB 2  /* See below */

/* elf_ehdr_t.e_type */
#define ET_NONE 0        /* no file */
#define ET_REL 1         /* relocatable file */
#define ET_EXEC 2        /* executable file */
#define ET_DYN 3         /* shared object file */
#define ET_CORE 4        /* core file */
#define ET_LOPROC 0xff00 /* processor-specific */
#define ET_HIPROC 0xffff /* processor-specific */

/* elf_ehdr_t.e_machine */
#define EM_NONE 0    /* no machine */
#define EM_M32 1     /* AT&T WE 32100 */
#define EM_SPARC 2   /* SPARC */
#define EM_386 3     /* Intel 80386 */
#define EM_68K 4     /* Motorola 68000 */
#define EM_88K 5     /* Motorola 88000 */
#define EM_860 7     /* Intel 80860 */
#define EM_MIPS 8    /* MIPS RS3000 */
#define EM_X86_64 62 /* Intel X86-64 */

/* elf_ehdr_t.e_version */
#define EV_NONE 0    /* Invalid version */
#define EV_CURRENT 1 /* Current version */

/* elf_ehdr_t.e_shstrndx */
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

/* elf_shdr_t.sh_type */
#define SHT_NULL 0          /* Marks an unused section header */
#define SHT_PROGBITS 1      /* information defined by the program */
#define SHT_SYMTAB 2        /* linker symbol table */
#define SHT_STRTAB 3        /* string table */
#define SHT_RELA 4          /* "Rela" type relocation entries */
#define SHT_HASH 5          /* a symbol hash table */
#define SHT_DYNAMIC 6       /* dynamic linking tables */
#define SHT_NOTE 7          /* 7 note information */
#define SHT_NOBITS 8        /* Uninitialized space; no space in the file */
#define SHT_REL 9           /* "Rel" type relocation entries */
#define SHT_SHLIB 10        /* Reserved */
#define SHT_DYNSYM 11       /* a dynamic loader symbol table */
#define SHT_LOOS 0x60000000 /* Environment-specific use */
#define SHT_HIOS 0x6FFFFFFF
#define SHT_LOPROC 0x70000000 /* Processor-specific use */
#define SHT_HIPROC 0x7FFFFFFF

#define PT_NULL 0          /* Unused entry */
#define PT_LOAD 1          /* Loadable segment */
#define PT_DYNAMIC 2       /* Dynamic linking tables */
#define PT_INTERP 3        /* Program interpreter path name */
#define PT_NOTE 4          /* Note segment */
#define PT_SHLIB 5         /* Reserved */
#define PT_PHDR 6          /* Program header table */
#define PT_TLS 7           /* Thread local storage segment */
#define PT_LOOS 0x60000000 /* Environment-specific use */
#define PT_HIOS 0x6FFFFFFF
#define PT_LOPROC 0x70000000 /* Processor-specific use */
#define PT_HIPROC 0x7FFFFFFF

#define SHF_WRITE 0x1     /* Section contains writable data */
#define SHF_ALLOC 0x2     /* Section is allocated in memory image of program */
#define SHF_EXECINSTR 0x4 /* Section contains executable instructions */
#define SHF_MASKOS 0x0F000000   /* Environment-specific use */
#define SHF_MASKPROC 0xF0000000 /* Processor-specific use */

#define PF_X 0x1               /* Execute permission */
#define PF_W 0x2               /* Write permission */
#define PF_R 0x4               /* Read permission */
#define PF_MASKOS 0x00FF0000   /* environment-specific use */
#define PF_MASKPROC 0xFF000000 /* processor-specific use */

#define STB_LOCAL 0  /* Not visible outside the object file */
#define STB_GLOBAL 1 /* Global symbol, visible to all object files */
#define STB_WEAK 2   /* Global scope, but with lower precedence than globals */
#define STB_LOOS 10  /* Environment-specific use */
#define STB_HIOS 12
#define STB_LOPROC 13 /* Processor-specific use */
#define STB_HIPROC 15

#define STT_NOTYPE 0  /* No type specified (e.g., an absolute symbol) */
#define STT_OBJECT 1  /* Data object */
#define STT_FUNC 2    /* Function entry point */
#define STT_SECTION 3 /* Symbol is associated with a section */
#define STT_FILE 4    /* Source file associated with the object file */
#define STT_LOOS 10   /* Environment-specific use */
#define STT_HIOS 12
#define STT_LOPROC 13 /* Processor-specific use */
#define STT_HIPROC 15

/* elf_rel.r_info */
#define R_X86_64_64 1
#define R_X86_64_COPY 5
#define R_X86_64_GLOB_DAT 6
#define R_X86_64_RELATIVE 8
#define R_X86_64_DPTMOD64 16

/* Supported thread-local storage relocations */
#define R_X86_64_TPOFF64 18 /* Offset in initial TLS block */

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i)&0xffffffffL)
#define ELF64_R_INFO(s, t) (((s) << 32) + ((t)&0xffffffffL))

typedef uint64_t elf_addr_t;
typedef uint64_t elf_off_t;
typedef unsigned short elf_half_t;
typedef unsigned int elf_word_t;
typedef signed int elf_sword_t;
typedef uint64_t elf_xword_t;
typedef int64_t elf_sxword_t;

typedef struct
{
    unsigned char e_ident[EI_NIDENT];
    elf_half_t e_type;
    elf_half_t e_machine;
    elf_word_t e_version;
    elf_addr_t e_entry;     /* entry point virtual address */
    elf_off_t e_phoff;      /* program header table offset */
    elf_off_t e_shoff;      /* (40) section header table offset */
    elf_word_t e_flags;     /* process-specific flags */
    elf_half_t e_ehsize;    /* ELF header size */
    elf_half_t e_phentsize; /* Program header table entry size */
    elf_half_t e_phnum;     /* Number of program header table entries */
    elf_half_t e_shentsize; /* Section header size */
    elf_half_t e_shnum;     /* Number of section headers */
    elf_half_t e_shstrndx;  /* Index of the string-table section header */
} elf_ehdr_t;

typedef struct
{
    elf_word_t sh_name;       /* Section name */
    elf_word_t sh_type;       /* Section type */
    elf_xword_t sh_flags;     /* Section attributes */
    elf_addr_t sh_addr;       /* Virtual address in memory */
    elf_off_t sh_offset;      /* Offset in file */
    elf_xword_t sh_size;      /* Size of section */
    elf_word_t sh_link;       /* Link to other section */
    elf_word_t sh_info;       /* Miscellaneous information */
    elf_xword_t sh_addralign; /* Address alignment boundary */
    elf_xword_t sh_entsize;   /* Size of entries, if section has table */
} elf_shdr_t;

typedef struct
{
    elf_word_t p_type;    /* Type of segment */
    elf_word_t p_flags;   /* Segment attributes */
    elf_off_t p_offset;   /* Offset in file */
    elf_addr_t p_vaddr;   /* Virtual address in memory */
    elf_addr_t p_paddr;   /* Reserved */
    elf_xword_t p_filesz; /* Size of segment in file */
    elf_xword_t p_memsz;  /* Size of segment in memory */
    elf_xword_t p_align;  /* Alignment of segment */
} elf_phdr_t;

typedef struct
{
    elf_word_t st_name;   /* Symbol name */
    unsigned char st_info;  /* Type and Binding attributes */
    unsigned char st_other; /* Reserved */
    elf_half_t st_shndx;  /* Section table index */
    elf_addr_t st_value;  /* Symbol value */
    elf_xword_t st_size;  /* Size of object (e.g., common) */
} elf_sym_t;

typedef struct
{
    elf_addr_t r_offset; /* Address of reference */
    elf_xword_t r_info;  /* Symbol index and type of relocation */
} elf_rel;

typedef struct
{
    elf_addr_t r_offset;   /* Address of reference */
    elf_xword_t r_info;    /* Symbol index and type of relocation */
    elf_sxword_t r_addend; /* Constant part of expression */
} elf_rela_t;

#define ELF_MAGIC 0x7d7ad33b
// clang-format off
#define ELF64_INIT { ELF_MAGIC, NULL, 0 }
// clang-format on

typedef struct
{
    /* Magic number (ELF_MAGIC) */
    unsigned int magic;

    /* File image */
    void* data;

    /* File image size */
    size_t size;
} elf_t;

int elf_test_header(const elf_ehdr_t* header);

int elf_from_buffer(void* buffer, size_t buffer_length, elf_t* elf);

int elf_load(const char* path, elf_t* elf);

int elf_unload(elf_t* elf);

int elf_get_dynamic_symbol_table(
    const elf_t* elf,
    const elf_sym_t** symtab,
    size_t* size);

void elf_dump_header(const elf_ehdr_t* ehdr);

void elf_dump_shdr(const elf_shdr_t* sh, size_t index);

void elf_dump(const elf_t* elf);

int elf_dump_sections(const elf_t* elf);

void elf_dump_symbol(const elf_t* elf, const elf_sym_t* sym);

int elf_dump_symbols(const elf_t* elf);

int elf_find_symbol_by_name(
    const elf_t* elf,
    const char* name,
    elf_sym_t* sym);

const char* elf_get_string_from_dynstr(
    const elf_t* elf,
    elf_word_t offset);

int elf_find_dynamic_symbol_by_name(
    const elf_t* elf,
    const char* name,
    elf_sym_t* sym);

int elf_find_dynamic_symbol_by_address(
    const elf_t* elf,
    elf_addr_t addr,
    unsigned int type, /* STT_? */
    elf_sym_t* sym);

int elf_find_symbol_by_address(
    const elf_t* elf,
    elf_addr_t addr,
    unsigned int type, /* STT_? */
    elf_sym_t* sym);

int elf_find_section(
    const elf_t* elf,
    const char* name,
    unsigned char** data,
    size_t* size);

const char* elf_get_string_from_shstrtab(
    const elf_t* elf,
    elf_word_t offset);

const char* elf_get_string_from_strtab(
    const elf_t* elf,
    elf_word_t offset);

int elf_add_section(
    elf_t* elf,
    const char* name,
    unsigned int type,
    const void* secdata,
    size_t secsize);

int elf_remove_section(elf_t* elf, const char* name);

void elf_dump_section_names(const elf_t* elf);

void elf_dump_strings(const elf_t* elf);

int elf_find_section_header(
    const elf_t* elf,
    const char* name,
    elf_shdr_t* shdr);

int elf_visit_symbols(
    const elf_t* elf,
    int (*visit)(const elf_sym_t* sym, void* data),
    void* data);

/* Load relocations (size will be a multiple of the page size) */
int elf_load_relocations(
    const elf_t* elf,
    void** data,
    size_t* size);

/* Get the segment with the given index; return NULL on error */
void* elf_get_segment(const elf_t* elf, size_t index);

/* Get the section header with the given index; return NULL on error */
elf_shdr_t* elf_get_section_header(
    const elf_t* elf,
    size_t index);

/* Get the program header with the given index; return NULL on error */
elf_phdr_t* elf_get_program_header(
    const elf_t* elf,
    size_t index);

/* Get pointer to the elf_ehdr_t */
elf_ehdr_t* elf_get_header(const elf_t* elf);

/* Return the name of the function that contains this address */
const char* elf_get_function_name(
    const elf_t* elf,
    elf_addr_t addr);

/*
**==============================================================================
**
** elf_image_t:
**
**==============================================================================
*/

typedef struct elf_segment
{
    /* Pointer to segment from ELF file */
    void* filedata;

    /* Size of this segment in the ELF file */
    size_t filesz;

    /* Size of this segment in memory */
    size_t memsz;

    /* Offset of this segment within file */
    uint64_t offset;

    /* Virtual address of this segment */
    uint64_t vaddr;

    /* Memory protection flags: (PF_R | PF_W | PF_X) */
    uint32_t flags;
}
elf_segment_t;

typedef struct elf_image
{
    elf_t elf;
    elf_segment_t* segments;
    size_t num_segments;
    void* image_data;
    size_t image_size;
    void* reloc_data;
    size_t reloc_size;
}
elf_image_t;

typedef int (*elf_add_page_t)(
    void* arg,
    uint64_t base_addr,
    uint64_t addr,
    uint64_t src,
    bool read,
    bool write,
    bool exec,
    bool extend);

int elf_image_from_section(
    elf_image_t* from_elf, 
    const char* section_name, 
    elf_image_t* to_elf);

int elf_image_load(const char* path, elf_image_t* image);

void elf_image_free(elf_image_t* image);

void elf_image_dump(const elf_image_t* image);

int elf_image_load_pages(
    elf_image_t* image,
    uint64_t dest_base_addr,
    uint64_t dest_size,
    elf_add_page_t add_page,
    void* add_page_arg,
    uint64_t* vaddr);

#endif /* _LIBOS_ELF_H */
