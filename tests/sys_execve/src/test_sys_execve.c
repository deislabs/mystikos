// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* These marco should be included like #include <linux/fcntl.h>
but there is decleration conflicts */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

typedef void (*test_case_t)(void);

void expect(int expected, int actual, const char* msg)
{
    if (expected != actual)
        fprintf(stderr, ">>> %s, got: %d\n", msg, errno);
}

/*
SYS_execve related test cases
*/

void test_absolute_path()
{
    printf("Running test_absolute_path\n");
    const char* filename = "/bin/echo";
    char* const argv[] = {filename, "test_absolute_path", 0};
    execve(filename, argv, NULL);
}

void test_absolute_path_with_symlink()
{
    printf("Running test_absolute_path_with_symlink\n");
    const char* filename = "/symlink/to_bin/echo";
    char* const argv[] = {filename, "test_absolute_path_with_symlink", 0};
    execve(filename, argv, NULL);
}

void test_executable_with_symlink()
{
    printf("Running test_executable_with_symlink\n");
    const char* filename = "/symlink/to_echo";
    char* const argv[] = {filename, "test_executable_with_symlink", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_1()
{
    printf("Running test_relative_path_1\n");

    const char* filename = "./bin/echo";
    char* const argv[] = {filename, "test_relative_path_1", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_2()
{
    printf("Running test_relative_path_2\n");

    if (chdir("/bin") != 0)
        assert(0 && "Failed to change dir to /bin");

    const char* filename = "./echo";
    char* const argv[] = {filename, "test_relative_path_2", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_3()
{
    printf("Running test_relative_path_3\n");

    if (chdir("/bin") != 0)
        assert(0 && "Failed to change dir to /bin");

    const char* filename = "./../bin/echo";
    char* const argv[] = {filename, "test_relative_path_3", 0};
    execve(filename, argv, NULL);
}

// Test invalid filename
void test_relative_path_4()
{
    printf("Running test_relative_path_4\n");

    const char* filename = "./none/exist/relative/path";
    char* const argv[] = {filename, "test_relative_path_4", 0};
    int ret = execve(filename, argv, NULL);

    expect(-1, ret, "execve should return -1");
    expect(ENOENT, errno, "errno should be ENOENT");
    exit(0);
}

void test_relative_path_5()
{
    printf("Running test_relative_path_5\n");

    if (chdir("/bin") != 0)
        assert(0 && "Failed to change dir to /bin");

    const char* filename = "echo";
    char* const argv[] = {filename, "test_relative_path_5", 0};
    execve(filename, argv, NULL);
}

void test_relative_path_with_symlink()
{
    printf("Running test_relative_path_with_symlink\n");

    if (chdir("/bin") != 0)
        assert(0 && "Failed to change dir to /bin");

    const char* filename = "../symlink/to_bin/echo";
    char* const argv[] = {filename, "test_relative_path_with_symlink", 0};
    execve(filename, argv, NULL);
}

/*
SYS_execveat related test cases
*/

// Pathname is absolute
void test_execveat_absolute_pathname_then_ok()
{
    printf("Running test_execveat_absolute_pathname_then_ok\n");

    const char* pathname = "/bin/echo";
    char* const argv[] = {
        pathname, "test_execveat_absolute_pathname_then_ok", 0};
    syscall(SYS_execveat, 0, pathname, argv, 0, 0);
}

// Pathname is relative, dirfd is valid directory
void test_execveat_relative_pathname_and_valid_dirfd_then_ok()
{
    printf("Running test_execveat_relative_pathname_and_valid_dirfd_then_ok\n");

    const int dirfd_bin = open("/bin", O_RDONLY);
    const char* pathname = "echo";
    char* const argv[] = {
        pathname, "test_execveat_relative_pathname_and_valid_dirfd_then_ok", 0};
    syscall(SYS_execveat, dirfd_bin, pathname, argv, 0, 0);
}

// Pathname is relative, dirfd points to a file, not directory
void test_execveat_relative_pathname_and_dirfd_is_file_then_enotdir()
{
    printf("Running "
           "test_execveat_relative_pathname_and_dirfd_is_file_then_enotdir\n");

    const int dirfd_bin = open("/bin/echo", O_RDONLY);
    const char* pathname = "echo";
    char* const argv[] = {pathname, "should not see this", 0};
    int ret = syscall(SYS_execveat, dirfd_bin, pathname, argv, 0, 0);

    expect(-1, ret, "execveat should return -1");
    expect(ENOTDIR, errno, "errno should be ENOTDIR");
    exit(0);
}

// Pathname is relative, dirfd is special value AT_FDCWD
// Same as execve
void test_execveat_relative_pathname_and_dirfd_at_fdcwd_then_ok()
{
    printf(
        "Running test_execveat_relative_pathname_and_dirfd_at_fdcwd_then_ok\n");

    if (chdir("/bin") != 0)
        assert(0 && "Failed to change dir to /bin");

    const int dirfd_bin = AT_FDCWD;
    const char* pathname = "echo";
    char* const argv[] = {
        pathname,
        "test_execveat_relative_pathname_and_dirfd_at_fdcwd_then_ok",
        0};
    syscall(SYS_execveat, dirfd_bin, pathname, argv, 0, 0);
}

// Pathname is an empty string, flag set to AT_EMPTY_PATH
// And dirfd points to an executable
void test_execveat_empty_pathname_and_flag_at_empty_path_and_valid_dirfd_then_ok()
{
    printf("Running "
           "test_execveat_empty_pathname_and_flag_at_empty_path_and_valid_"
           "dirfd_then_ok\n");

    // This program should run instead
    const int dirfd_echo = open("/bin/echo", O_RDONLY);
    const char* pathname = "";
    char* const argv[] = {pathname,
                          "test_execveat_empty_pathname_and_flag_at_empty_path_"
                          "and_valid_dirfd_then_ok",
                          0};
    syscall(SYS_execveat, dirfd_echo, pathname, argv, 0, AT_EMPTY_PATH);
}

// Pathname is an empty string, flag NOT set to AT_EMPTY_PATH
// And dirfd points to any executable
// Same as invalid pathname
void test_execveat_empty_pathname_and_empty_flag_and_any_dirfd_then_enoent()
{
    printf("Running "
           "test_execveat_empty_pathname_and_empty_flag_and_any_dirfd_then_"
           "enoent\n");

    const int dirfd_bin = open("/bin/echo", O_RDONLY);
    const char* pathname = "";
    char* const argv[] = {pathname, "should not see this", 0};
    int ret = syscall(SYS_execveat, dirfd_bin, pathname, argv, 0, 0);

    expect(-1, ret, "execveat should return -1");
    expect(ENOENT, errno, "errno should be ENOENT");
    exit(0);
}

// Pathname is an empty string, flag set to AT_EMPTY_PATH
// And dirfd points to a directory
void test_execveat_empty_pathname_and_flag_at_empty_path_and_dirfd_directory_then_eacces()
{
    printf("Running "
           "test_execveat_empty_pathname_and_flag_at_empty_path_and_dirfd_"
           "directory_then_eacces\n");

    const int dirfd_echo = open("/bin", O_RDONLY);
    const char* pathname = "";
    char* const argv[] = {pathname, "should not see this", 0};
    int ret =
        syscall(SYS_execveat, dirfd_echo, pathname, argv, 0, AT_EMPTY_PATH);

    expect(-1, ret, "execveat should return -1");
    expect(EACCES, errno, "errno should be EACCES");
    exit(0);
}

// symlink as part of pathname
void test_execveat_symlink_in_path_and_symlink_nofollow_flag_then_ok()
{
    printf("Running "
           "test_execveat_symlink_in_path_and_symlink_nofollow_flag_then_ok\n");

    const int dirfd = AT_FDCWD;
    const char* pathname = "/symlink/to_bin/echo";
    char* const argv[] = {
        pathname,
        "test_execveat_symlink_in_path_and_symlink_nofollow_flag_then_ok",
        0};

    syscall(SYS_execveat, dirfd, pathname, argv, 0, AT_SYMLINK_NOFOLLOW);
}

// last component of pathname is symlink
void test_execveat_symlink_end_path_and_symlink_nofollow_flag_then_eloop()
{
    printf("Running "
           "test_execveat_symlink_end_path_and_symlink_nofollow_flag_then_"
           "eloop\n");

    const int dirfd = AT_FDCWD;
    const char* pathname = "/symlink/to_echo";
    char* const argv[] = {pathname, "should not see this", 0};

    int ret =
        syscall(SYS_execveat, dirfd, pathname, argv, 0, AT_SYMLINK_NOFOLLOW);

    expect(-1, ret, "execveat should return -1");
    expect(ELOOP, errno, "errno should be ELOOP");
    exit(0);
}

void create_symlink()
{
    // assume folder symlink already exists

    int ret = symlink("/bin", "/symlink/to_bin");
    expect(0, ret, "Failed to created symlink to_bin");

    ret = symlink("/bin/echo", "/symlink/to_echo");
    expect(0, ret, "Failed to created symlink to_echo");
}

int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        printf("Usage: test [index of test case (0 based)]\n"
               "\tFor example, to run second test : ./test 1\n");
        return 0;
    }

    create_symlink();

    const int number_tests = 18;
    const test_case_t test_cases[] = {
        test_absolute_path,
        test_absolute_path_with_symlink,
        test_executable_with_symlink,
        test_relative_path_1,
        test_relative_path_2,
        test_relative_path_3,
        test_relative_path_4,
        test_relative_path_5,
        test_relative_path_with_symlink,
        test_execveat_absolute_pathname_then_ok,
        test_execveat_relative_pathname_and_valid_dirfd_then_ok,
        test_execveat_relative_pathname_and_dirfd_is_file_then_enotdir,
        test_execveat_relative_pathname_and_dirfd_at_fdcwd_then_ok,
        test_execveat_empty_pathname_and_flag_at_empty_path_and_valid_dirfd_then_ok,
        test_execveat_empty_pathname_and_flag_at_empty_path_and_dirfd_directory_then_eacces,
        test_execveat_empty_pathname_and_empty_flag_and_any_dirfd_then_enoent,
        test_execveat_symlink_in_path_and_symlink_nofollow_flag_then_ok,
        test_execveat_symlink_end_path_and_symlink_nofollow_flag_then_eloop};

    int selection = atoi(argv[1]);
    if (selection >= number_tests)
    {
        fprintf(
            stderr,
            "Invalid selection %d. Number should be <%d\n",
            selection,
            number_tests);
        return 1;
    }

    (test_cases[selection])();

    assert(0 && "Should not reach here");
    return 1;
}
