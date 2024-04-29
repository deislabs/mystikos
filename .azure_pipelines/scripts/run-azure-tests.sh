#!/usr/bin/env bash
# shellcheck disable=SC2154
# Usage: run-azure-tests.sh <Solutions_DIR>
set -e
set -x

az --version
az account show
AZURE_SUBSCRIPTION_ID="$(az account show --query id --output tsv)"
export AZURE_SUBSCRIPTION_ID
export AZURE_KEYVAULT_HSM_URL="${AZURE_KEYVAULT_URL}"
export ADLS_GEN2_CONNECTION_STRING=${STANDARD_STORAGE_CONNECTION_STRING}
export PREMIUM_FILE_CONNECTION_STRING=${STANDARD_STORAGE_CONNECTION_STRING}

if [[ -z "${AZURE_KEYVAULT_URL}" || -z "${AZURE_SUBSCRIPTION_ID}" || -z "${STANDARD_STORAGE_CONNECTION_STRING}" ]]; then
    echo "Missing environment variables"
    exit 1
fi

for test_suite in "$@"
do
	RUN_AZURE_TESTS=1 make tests -C "${test_suite}"
done
