// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>

int __open_2(const char* file, int oflag)
{
    return open(file, oflag);
}
