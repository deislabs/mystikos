#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include "process.h"

int process_is_being_traced(void)
{
    int ret = 0;
    FILE* is = NULL;
    char line[1024];

    /* open "/proc/<pid>/status" for read */
    if (!(is = fopen("/proc/self/status", "r")))
    {
        ret = -ENOENT;
        goto done;
    }

    /* read "/proc/<pid>/status" line-by-line */
    while (fgets(line, sizeof(line), is))
    {
        pid_t pid = -1;

        /* if this line is the "TracerPid" field */
        if (sscanf(line, "TracerPid:\t%d", &pid) == 1)
        {
            if (pid == 0)
            {
                ret = 0;
                goto done;
            }
            else if (pid > 0)
            {
                ret = 1;
                goto done;
            }
            else
            {
                ret = -ENOENT;
                goto done;
            }
        }
    }

    ret = -ENOENT;

done:

    if (is)
        fclose(is);

    return ret;
}
