#!/bin/bash
set -e
make run-list TESTFILE=tests.passed
make run-list TESTFILE=tests.passed.1
