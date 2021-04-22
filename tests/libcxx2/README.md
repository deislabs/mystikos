# LIBCXX tests (built on UBUNTU)

This suite contains Libcxx tests from llvm-project that are built and run in ubuntu.

## running tests

```bash
make tests
```

The tests have been segregated into files based on their state (running/failing/how are they failing). The following key applies -

ALL TESTS

1. [tests.all](tests.all): All the tests in libcxx that we have (pass + fail)

PASSING

1. [tests.passed](tests.passed): All tests that pass

FAILING

1. [tests.failed](tests.failed): Tests that fail
2. [tests.failedubuntu](tests.failedubuntu): Tests that fail outside of mystikos
3. [tests.remove](tests.remove): Flaky tests that cause memory errors in the pipeline
