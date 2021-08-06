#ifndef _SECTIONS_H
#define _SECTIONS_H

#include <stddef.h>

typedef struct sections
{
    void* mystenc_data;
    size_t mystenc_size;
    void* libmystcrt_data;
    size_t libmystcrt_size;
    void* libmystkernel_data;
    size_t libmystkernel_size;
    void* mystrootfs_data;
    size_t mystrootfs_size;
    void* mystpubkeys_data;
    size_t mystpubkeys_size;
    void* mystroothashes_data;
    size_t mystroothashes_size;
    void* mystconfig_data;
    size_t mystconfig_size;
} sections_t;

int load_sections(const char* path, sections_t* sections);

void free_sections(sections_t* sections);

#endif /* _SECTIONS_H */
