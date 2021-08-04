#!/bin/bash

##==============================================================================
##
## Wrap the given source file with a preamble and postamble
##
##==============================================================================

if [ "$#" != "1" ]; then
    echo "Usage: $0 <source-file>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "$0: no such file: $1"
    exit 1
fi

cp $1 $1.bak

cat > $1 <<EOF
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
EOF

cat $1.bak >> $1

cat >> $1 <<EOF
#pragma GCC diagnostic pop
EOF

rm -f $1.bak
