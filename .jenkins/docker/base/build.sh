#!/usr/bin/env bash
#
# This script is used to build associated Dockerfile
# Recommended to create a new directory to build with a minimal build context

set -e

SOURCE_DIR=$(dirname "$0")
BUILD_DIR="${PWD}"
UBUNTU_VERSION="18.04"
IMAGE_TAG="latest"

usage() {
    echo "Usage: $0 -m <string> -o <string> [OPTIONS..]" 1>&2
    echo "Create a base Docker image for Mystikos" 1>&2
    echo "  -m     Mystikos release version (Example: 0.5.0) or path to Mystikos tar.gz"
    echo "           See https://github.com/deislabs/mystikos/releases for release versions"
    echo "  -o     Open Enclave Base Docker Image tag."
    echo "           See https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md for release versions"
    echo ""
    echo "Options:" 1>&2
    echo "  -u     Ubuntu release version [Default: 18.04]" 1>&2
    echo "  -t     Tag for the Docker image [Default: latest]" 1>&2
    exit 1
}

# Parse options
while getopts "hm:o:u::t::" option; do
    case "${option}" in
       m) MYSTIKOS_RELEASE_VERSION="${OPTARG}"
          ;;
       o) OPENENCLAVE_BASE_IMAGE_TAG="${OPTARG}"
          ;;
       u) UBUNTU_VERSION="${OPTARG}"
          ;;
       t) IMAGE_TAG="${OPTARG}"
          ;;
       *) usage
          ;;
    esac
done

# Catch extra parameters
shift "$((OPTIND-1))"
if [[ ! -z "${1}" ]]; then
    echo "Unknown parameter: ${1}" 1>&2
    exit 1
fi

# Check versions
if [[ -z ${MYSTIKOS_RELEASE_VERSION+x} ]] || [[ -z ${OPENENCLAVE_BASE_IMAGE_TAG+x} ]]; then
    echo "Mystikos release version (-m) and Open Enclave base Docker image tag (-o) must be set"
    echo "Mystikos release version: ${MYSTIKOS_RELEASE_VERSION}"
    echo "Open Enclave base Docker image tag: ${OPENENCLAVE_BASE_IMAGE_TAG}"
    echo ""
    usage
fi

# Set Ubuntu Codename
case "${UBUNTU_VERSION}" in
    18.04) UBUNTU_CODENAME="bionic"
           ;;
    20.04) UBUNTU_CODENAME="focal"
           ;;
esac

if [[ "${MYSTIKOS_RELEASE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Download Mystikos release
    MYST_TARBALL="Ubuntu-${UBUNTU_VERSION//.}_mystikos-${MYSTIKOS_RELEASE_VERSION}-x86_64.tar.gz"
    if [[ -f "${BUILD_DIR}/${MYST_TARBALL}" ]]; then
        rm "${BUILD_DIR}/${MYST_TARBALL}"
    fi
    wget \
    --directory-prefix="${BUILD_DIR}" \
    --no-verbose \
    --tries=3 \
    --waitretry=3 \
    https://github.com/deislabs/mystikos/releases/download/v${MYSTIKOS_RELEASE_VERSION}/${MYST_TARBALL}
else
    echo "Mystikos release version does not match [0-9]+.[0-9]+.[0-9]+ ... assuming local tarball path."
    MYST_TARBALL="${MYSTIKOS_RELEASE_VERSION}"
fi

# Build Docker image
set -x
DOCKER_BUILDKIT=1 docker build \
  --build-arg UBUNTU_VERSION="${UBUNTU_VERSION}" \
  --build-arg OPENENCLAVE_BASE_IMAGE_TAG="${OPENENCLAVE_BASE_IMAGE_TAG}" \
  --build-arg MYSTIKOS_TARBALL="${MYST_TARBALL}" \
  --no-cache \
  --file "${SOURCE_DIR}/Dockerfile" \
  --tag "mystikos-${UBUNTU_CODENAME}:${IMAGE_TAG}" \
  "${BUILD_DIR}"
