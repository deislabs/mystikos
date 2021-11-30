#!/usr/bin/env bash

az logout || true
az cache purge
az account clear
