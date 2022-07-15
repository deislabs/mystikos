#!/usr/bin/env bash
set -e

make -j tests ALLTESTS=1 VERBOSE=1
