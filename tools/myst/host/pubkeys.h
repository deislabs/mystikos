#ifndef MYST_HOST_PUBKEYS_H
#define MYST_HOST_PUBKEYS_H

#include <limits.h>
#include <stddef.h>

void create_pubkeys_file(
    const char* pubkeys[],
    size_t num_pubkeys,
    char pubkeys_path[PATH_MAX]);

void get_pubkeys_options(
    int* argc,
    const char* argv[],
    const char* pubkeys[],
    size_t max_pubkeys,
    size_t* num_pubkeys);

#endif /* MYST_HOST_PUBKEYS_H */
