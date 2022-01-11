#!/bin/bash
# This script will be invoked by github fuzzing workflow.
set -ex
ROOT_DIR=$(git rev-parse --show-toplevel)
AZCOPY_DIR="$ROOT_DIR/build/tools/azcopy"
BUILD_DIR="$ROOT_DIR/build"
ONEFUZZ_SETUP_DIR="$ROOT_DIR/build/myst_onefuzz_setup"
PROJECT="mystikos"
POOL="mystikos-pool"
DURATION=24
GITHUB_ISSUES_NOTIFICATION="$ROOT_DIR/.github/workflows/github-issues.json"

[[ -d "$AZCOPY_DIR" ]] && rm -rf "$AZCOPY_DIR"
mkdir -p "$AZCOPY_DIR"
pushd "$AZCOPY_DIR"
wget -O azcopy.tgz https://aka.ms/downloadazcopy-v10-linux
tar zxvf azcopy.tgz
mv azcopy_linux_amd64*/* "$AZCOPY_DIR"
export AZCOPY="$AZCOPY_DIR/azcopy"
popd

pushd "$ONEFUZZ_SETUP_DIR"
onefuzz template libfuzzer basic $PROJECT "fuzz-exec-linux" $GITHUB_SHA $POOL \
    --target_exe "./bin/fuzz-exec-linux" \
    --target_workers 2 \
    --target_timeout 30 \
    --duration $DURATION \
    --setup_dir $ONEFUZZ_SETUP_DIR \
    --notification_config @"$GITHUB_ISSUES_NOTIFICATION" \
    --colocate_all_tasks
popd
