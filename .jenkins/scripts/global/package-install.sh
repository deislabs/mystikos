#!/usr/bin/env bash
set -e

rm -rf build
make release-build
sudo dpkg -i mystikos-*-x86_64.deb
rm -rf build

export PATH="$PATH:/opt/mystikos/bin"
export BINDIR=/opt/mystikos/bin
