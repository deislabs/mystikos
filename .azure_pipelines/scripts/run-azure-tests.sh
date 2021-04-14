#!/usr/bin/env bash
# shellcheck disable=SC2154
# Usage: run-azure-tests.sh <Solutions_DIR>
set -e
set -x

az --version
az account show
export AZURE_CLIENT_ID="${servicePrincipalId}"
export AZURE_TENANT_ID="${tenantId}"
export AZURE_CLIENT_SECRET="${servicePrincipalKey}"
AZURE_SUBSCRIPTION_ID="$(az account show --query id --output tsv)"
export AZURE_SUBSCRIPTION_ID

if [[ -z "${AZURE_CLIENT_ID}" || -z "${AZURE_CLIENT_SECRET}" || -z "${AZURE_TENANT_ID}" || -z "${AZURE_KEYVAULT_URL}" || -z "${AZURE_SUBSCRIPTION_ID}" ]]; then
    echo "Missing environment variables"
    exit 1
fi

RUN_AZURE_TESTS=1 make tests -C "$1"
