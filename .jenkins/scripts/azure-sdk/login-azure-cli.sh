#!/usr/bin/env bash

az login --service-principal -u ${SERVICE_PRINCIPAL_ID} -p ${SERVICE_PRINCIPAL_PASSWORD} --tenant ${TENANT_ID} >> /dev/null
az account set -s ${AZURE_SUBSCRIPTION_ID}
