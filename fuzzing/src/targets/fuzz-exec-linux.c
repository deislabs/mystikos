// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <syscallfuzzer.h>

extern void InitializeEnclaveFuzzer();
extern void DestroyEnclaveFuzzer();
extern const char* set_program_file(const char* program);
extern int exec_action(int argc, const char* argv[], const char* envp[]);

const uint8_t* fuzzer_data;
size_t fuzzer_data_size;

const uint8_t* get_fuzzer_payload()
{
    return fuzzer_data;
}

size_t get_fuzzer_payload_size()
{
    return fuzzer_data_size;
}

extern void set_syscall_fuzzer_payload(syscall_fuzzer_payload* payload);
#define PATH_MAX 255
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < sizeof(syscall_fuzzer_payload))
        return 0;

    set_syscall_fuzzer_payload((syscall_fuzzer_payload*)data);
    fuzzer_data = (uint8_t*)data;
    fuzzer_data_size = size;

    char process_path[PATH_MAX] = {0};
    if (readlink("/proc/self/exe", process_path, PATH_MAX - 1) == -1)
        return false;

    char rootfs_path[PATH_MAX] = {0};
    strcpy(rootfs_path, process_path);
    int len = strlen(rootfs_path);
    while (len > 0)
    {
        if (rootfs_path[len] == '/')
            break;
        len--;
    }

    if (len > 0)
    {
        rootfs_path[len + 1] = '\0';
        strcat(rootfs_path, "rootfs");
        printf("process: %s \nrootfs: %s\n", process_path, rootfs_path);
    }

    char* argv[] = {
        process_path, "fuzz-exec-linux", rootfs_path, "/syscallfuzzer", NULL};

    char* envp[] = {"env1", "0", NULL};
    InitializeEnclaveFuzzer();
    set_program_file(argv[0]);
    (void)exec_linux_action(4, argv, envp);
    DestroyEnclaveFuzzer();
    return 0;
}

void LLVMFuzzerFinalize()
{
}
