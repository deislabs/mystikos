# Libc Tests

The tests have been segregated into files based on their state (running/failing/how are they failing). The following key applies -

ALL TESTS

1. [tests_alltests.txt](tests_alltests.txt): All the tests in libc that we have (pass + fail)
2. [tests_allrunning.txt](tests_allrunning.txt): All tests that run without the tests that hang ( pass + fail - hang)

PASSING

1. [tests_passed.txt](tests_passed.txt): All tests that pass

FAILING

1. [tests_hanging.txt](tests_hanging.txt): All the tests that hang (do not complete)
2. [tests_unhandled_syscalls.txt](tests_unhandled_syscalls.txt): Tests that fail due to an unimplemented syscall in mystikos.
3. [tests_other_errors.txt](tests_other_errors.txt): Tests that fail due to errors like invalid return value, etc.
