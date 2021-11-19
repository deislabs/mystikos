#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

#include "tempfile.h"
#include <myst/eraise.h>

static pid_t _pid;

void myst_set_tempfile_pid(pid_t pid)
{
    _pid = pid;
}

long myst_tcall_get_tempfile_name(char* buf, size_t size)
{
    long ret = 0;
    static size_t _num;
    static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
    bool locked = false;
    char dirname[PATH_MAX];

    if (!buf || !size)
        ERAISE(-EINVAL);

    pthread_mutex_lock(&_lock);
    locked = true;

    /* create the PID directory (or verify it is a directory) */
    {
        struct stat statbuf;

        snprintf(dirname, sizeof(dirname), "/tmp/myst-pid-%u", _pid);

        if (stat(dirname, &statbuf) == 0)
        {
            if (!S_ISDIR(statbuf.st_mode))
                ERAISE(-ENOTDIR);
        }
        else if (mkdir(dirname, 0775) != 0)
        {
            ERAISE(-errno);
        }
    }

    /* format the temp file name */
    {
        int len = snprintf(buf, size, "%s/%zu", dirname, ++_num);

        if (len < 0 || (size_t)len >= size)
        {
            memset(buf, 0, size);
            ERAISE(-ENAMETOOLONG);
        }
    }

done:

    if (locked)
        pthread_mutex_unlock(&_lock);

    return ret;
}
