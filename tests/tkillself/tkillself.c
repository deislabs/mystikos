// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <signal.h>
#include <syscall.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    syscall(SYS_tkill, getpid(), SIGABRT);
    return 0;
}
