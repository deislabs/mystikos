#include <glob.h>
#include <stdio.h>

#include "copy_file.h"

const char* _host_paths[] = {"/sys/devices/system/cpu/cpu*/cache/index*/size",
                             "/sys/devices/system/cpu/kernel_max",
                             "/sys/devices/system/cpu/possible",
                             "/sys/devices/system/cpu/present",
                             "/sys/devices/system/node/possible"};

glob_t _pglob;

int get_host_file_copy_list(myst_args_t* copy_host_files)
{
    int ret = 0;

    for (size_t i = 0; i < sizeof(_host_paths) / sizeof(_host_paths[0]); i++)
    {
        const char* path_pattern = _host_paths[i];
        int flag = i ? GLOB_APPEND : 0;
        ret = glob(path_pattern, flag, NULL, &_pglob);
        if (ret < 0)
        {
            fprintf(
                stderr,
                "get_host_file_copy_list(): glob failed: ret=%d\n",
                ret);
        }
    }

    for (size_t i = 0; i < _pglob.gl_pathc; i++)
    {
        myst_args_append1(copy_host_files, _pglob.gl_pathv[i]);
    }

    return ret;
}

void free_host_file_copy_list()
{
    globfree(&_pglob);
}
