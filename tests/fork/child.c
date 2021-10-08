// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int just_return()
{
    printf("In execl process\n");
    return 10;
}

int kill_usr1()
{
    printf("In execl process. Sending self a SIGUSR1\n");
    kill(getpid(), SIGUSR1);
    return 12;
}

int main(int argc, const char* argv[])
{
    if (argc == 2)
    {
        if (strcmp(argv[1], "just_return") == 0)
        {
            return just_return();
        }
        else if (strcmp(argv[1], "kill_usr1") == 0)
        {
            return kill_usr1();
        }
        else
        {
            assert("invalid argument to the child" == NULL);
            return 2;
        }
    }
    else
    {
        assert("invalid number of arguments to the child" == NULL);
        return 2;
    }

    return 3;
}