#!/usr/bin/env bash

az login --identity >> /dev/null
az account set -s ${AZURE_SUBSCRIPTION_ID}
