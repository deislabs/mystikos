#!/usr/bin/env bash
set -e

sudo rm -rf $(git ls-files --others --directory)
make distclean
make -j build
