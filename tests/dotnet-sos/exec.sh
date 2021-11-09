#!/bin/bash
# USAGE: exec.sh <PATH-TO-OELLDB> <MYST-PATH> <EXEC-FLAVOR> <OPTS>
function log_and_exit()
{
    echo "==================================="
    cat stdouterr.txt
    rm stdouterr.txt
    exit 1
}

$1 -b -o 'command script import sos_test' \
	-o "quit" \
	-- $2 $3 $4 ext2fs \
	--memory-size 768M \
	/app/hello > stdouterr.txt 2>&1

if [ "$?" != "0" ]; then
    log_and_exit
fi

# Check no assertions failed
grep -q "AssertionError" stdouterr.txt
if [ "$?" == "0" ]; then
    echo "Assertions failed!"
    log_and_exit
fi

# Check managed breakpoint was set
grep -q "Setting breakpoint: breakpoint set --address [0-9A-Fa-fx]* \[hello.Program.Main(System.String\[\])\]" stdouterr.txt
if [ "$?" != "0" ]; then
    echo "Managed breakpoint was not set!"
    log_and_exit
fi

# Check hello.Program.Main figures in clrstack
grep -q "[0-9A-Fa-f]* [0-9A-Fa-f]* hello.Program.Main(System.String\[\])" stdouterr.txt
if [ "$?" != "0" ]; then
    echo "clrstack didn't show hello.Program.Main"
    log_and_exit
fi

# Check clrstack at Debugger.Break()
grep -q "[0-9A-Fa-f]* [0-9A-Fa-f]* \[HelperMethodFrame: [0-9A-Fa-f]*\] System.Diagnostics.Debugger.BreakInternal()" stdouterr.txt
if [ "$?" != "0" ]; then
    echo "clrstack check for Debugger.Break() failed!"
    log_and_exit
fi

rm stdouterr.txt