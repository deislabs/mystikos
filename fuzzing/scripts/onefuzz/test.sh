#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
BUILD_DIR="$ROOT_DIR/build"
ONEFUZZ_SETUP_DIR="$ROOT_DIR/build/myst_onefuzz_setup"

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT
function ctrl_c() {
   exit
}

pushd "$ONEFUZZ_SETUP_DIR"
for i in {0..1000..1}
  do
      ASAN_OPTIONS="detect_leaks=0" ./bin/fuzz-exec-linux -rss_limit_mb=8192 -timeout=5
done
popd
