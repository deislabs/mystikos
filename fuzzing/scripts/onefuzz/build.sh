#!/bin/bash
set -ex
# This script will be invoked by github fuzzing workflow.

ROOT_DIR=$(git rev-parse --show-toplevel)
MYST_BUILD="$ROOT_DIR/build"
MYST_INSTALL_PREFIX="$MYST_BUILD/myst_install"
MYST_INSTALL_PREFIX_TMP="/tmp/myst_install"
MYST_FUZZER_BUILD="$MYST_BUILD/myst_fuzzing"
MYST_FUZZER_PACKAGE="$MYST_BUILD/myst_fuzzer_package"
ONEFUZZ_SETUP_DIR="$MYST_BUILD/myst_onefuzz_setup"
MAKE_THREADS=$(nproc)

pushd "$ROOT_DIR"
rm -rf build
rm -rf "${MYST_INSTALL_PREFIX_TMP}"
mkdir -p "${MYST_INSTALL_PREFIX_TMP}"

make clean
make distclean
make MYST_PRODUCT_BUILD=1 -j ${MAKE_THREADS}
make MYST_PRODUCT_BUILD=1 MYST_PREFIX="${MYST_INSTALL_PREFIX_TMP}" install -j ${MAKE_THREADS}

make clean
make distclean
make MYST_PRODUCT_BUILD=1 MYST_FUZZING=1 -j ${MAKE_THREADS}

# create exec-linux package with syscallfuzzer as target
cp -r "${MYST_INSTALL_PREFIX_TMP}" "${MYST_INSTALL_PREFIX}"
mkdir -p ${MYST_FUZZER_PACKAGE}/appdir
mkdir -p ${MYST_FUZZER_PACKAGE}/appdir/files_fd_path
touch ${MYST_FUZZER_PACKAGE}/appdir/files_fd_path/testfile1
cp ${MYST_BUILD}/syscallfuzzer/output/bin/syscallfuzzer ${MYST_FUZZER_PACKAGE}/appdir/syscallfuzzer
${MYST_INSTALL_PREFIX}/bin/myst mkcpio ${MYST_FUZZER_PACKAGE}/appdir ${MYST_FUZZER_PACKAGE}/rootfs

# create onefuzz setup dir
mkdir -p "$ONEFUZZ_SETUP_DIR"
mkdir -p "$ONEFUZZ_SETUP_DIR/bin"
cp "$ROOT_DIR"/fuzzing/scripts/onefuzz/setup.sh "$ONEFUZZ_SETUP_DIR"
cp "$MYST_BUILD"/bin/myst "$ONEFUZZ_SETUP_DIR"/bin/fuzz-exec-linux
cp "$MYST_BUILD"/myst_fuzzer_package/rootfs "$ONEFUZZ_SETUP_DIR"/bin/rootfs
cp "$ROOT_DIR"/fuzzing/3rdparty/linux-sgx/build/linux/libsgx_enclave_common.so "$ONEFUZZ_SETUP_DIR"
cp -r "$MYST_BUILD/"lib "$ONEFUZZ_SETUP_DIR/"lib
popd
