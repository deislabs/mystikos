#include <stdlib.h>

char* __realpath_chk(const char* path, char* resolved_path, size_t resolved_len)
{
    return realpath(path, resolved_path);
}
