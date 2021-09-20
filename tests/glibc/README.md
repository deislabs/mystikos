# Glibc tests (built on Ubuntu OS)

This suite contains Glibc tests that are built and run on Ubuntu.

## running tests

```bash
make tests
```

To run a particular test:

```bash
make one TEST=testname
```

The tests have been segregated into files based on their state (running/failing/how are they failing). The following key applies -

ALL TESTS

1. [tests.all](tests.all): Superset - All the tests in glibc that we have (pass + fail + misc)

PASSING

1. [tests.passed](tests.passed): All tests that pass; run in our pipelines

FAILING

1. [tests.failed](tests.failed): Tests that fail due to scattered/miscelleneous causes with output
2. [tests.failedubuntu](tests.failedubuntu): Tests that fail outside of mystikos when run as an independant binary due to absence of supporting packages
3. [tests.remove](tests.remove): Flaky tests that cause errors in the pipeline
4. [tests.dockerlimitations](tests.dockerlimitations): These tests cause the docker to hang so we have currently excluded them
5. [tests.unsupportedrelocation37](tests.unsupportedrelocation37): These tests cause an `unsupported relocation 37` error in mystikos and need to be debugged
6. [tests.removegcov](tests.removegcov): These tests are flaky in the code coverage pipeline

## training the suite

In order to divide the suite into the above files, you can make use of the [run_tests_locally.sh](run_tests_locally.sh) script. It will iterate over whichever file you give it, and divide it into two files, containing "passed" or "other_errors" (failed) tests.
To make this process faster, change this line `OPTS += --memory-size=512m` in the [Makefile](Makefile) to allocate lesser memory for the process, since we are running one test at a time here.

```bash

Usage:

./run_tests_locally <filename>

eg:

./run_tests_locally tests.all

```