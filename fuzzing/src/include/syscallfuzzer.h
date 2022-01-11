// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

typedef struct _syscall_args
{
    long a1;
    long a2;
    long a3;
    long a4;
    long a5;
    long a6;
} syscall_args;

typedef struct _syscall_fuzzer_payload
{
    int rand;
    long syscall_id;
    syscall_args in_args;
    long return_value;
} syscall_fuzzer_payload;
