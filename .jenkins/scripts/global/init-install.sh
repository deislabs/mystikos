#!/usr/bin/env bash
set -e

sudo apt-get install \
  build-essential    \
  lcov               \
  python3-setuptools \
  python3-pip        \
  llvm-7             \
  libmbedtls-dev     \
  docker-ce          \
  python3-pip        \
  lldb-10 -y

docker system prune -a -f

df
