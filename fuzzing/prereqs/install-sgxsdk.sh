#!/bin/bash
set -e
if [[ ! -d "/opt/intel/sgxsdk" ]]; then
    sudo $1 <<EOF
no
/opt/intel
EOF
fi
