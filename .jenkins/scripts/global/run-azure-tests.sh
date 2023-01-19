#!/usr/bin/env bash
# shellcheck disable=SC2154
# Usage: run-azure-tests.sh <Solutions_DIR>

# Azure SDK tests require a service principal that has the following access on Azure:
# - contributor access to the subscription,
# - access policies for the Azure Key Vault. Specifically:
#   - Keys: Get, List, Update, Create, Delete, Backup, Decrypt, Encrypt, Purge
#   - Secrets: Get, List, Set, Delete, Backup, Purge
#   - Certificates: Get, List, Update, Create, Delete, Backup, Purge

set -e
set -x

az --version
az account show
export AZURE_CLIENT_ID="${servicePrincipalId}"
export AZURE_TENANT_ID="${tenantId}"
export AZURE_CLIENT_SECRET="${servicePrincipalKey}"
AZURE_SUBSCRIPTION_ID="$(az account show --query id --output tsv)"
export AZURE_SUBSCRIPTION_ID
export AZURE_KEYVAULT_HSM_URL="${AZURE_KEYVAULT_URL}"
export AAD_CLIENT_ID=${AZURE_CLIENT_ID}
export AAD_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
export AAD_TENANT_ID=${AZURE_TENANT_ID}
export ADLS_GEN2_CONNECTION_STRING=${STANDARD_STORAGE_CONNECTION_STRING}
export PREMIUM_FILE_CONNECTION_STRING=${STANDARD_STORAGE_CONNECTION_STRING}

if [[ -z "${AZURE_CLIENT_ID}" || -z "${AZURE_CLIENT_SECRET}" || -z "${AZURE_TENANT_ID}" || -z "${AZURE_KEYVAULT_URL}" || -z "${AZURE_SUBSCRIPTION_ID}" || -z "${STANDARD_STORAGE_CONNECTION_STRING}" ]]; then
    echo "Missing environment variables"
    exit 1
fi

# Build first
for test_suite in "$@"
do
	make -C "${test_suite}"
done

for test_suite in "$@"
do
	RUN_AZURE_TESTS=1 make tests -C "${test_suite}"
done

make -s summary