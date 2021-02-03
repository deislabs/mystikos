#ifndef MYST_HOST_ARCHIVE_H
#define MYST_HOST_ARCHIVE_H

#include <limits.h>
#include <stddef.h>

void create_archive(
    const char* pubkeys[],
    size_t num_pubkeys,
    const char* roothashes[],
    size_t num_roothashes,
    char archive_path[PATH_MAX]);

void get_archive_options(
    int* argc,
    const char* argv[],
    const char* pubkeys[],
    size_t max_pubkeys,
    size_t* num_pubkeys,
    const char* roothashes[],
    size_t max_roothashes,
    size_t* num_roothashes);

#endif /* MYST_HOST_ARCHIVE_H */
