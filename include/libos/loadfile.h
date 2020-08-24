#ifndef _LIBOS_LOADFILE_H
#define _LIBOS_LOADFILE_H

#include <stddef.h>

int libos_load_file(const char* path, void** data_out, size_t* size_out);

#endif /* _LIBOS_LOADFILE_H */
