#!/bin/bash
$1 -b -o 'command script import sos_test' \
	-o "quit" \
	-- $2 exec $3 ext2fs \
	--roothash=roothash \
	--memory-size $4 \
	/app/hello > stdouterr.txt 2>&1

if [ "$?" != "0" ]; then
    exit 1
fi

# Check no assertions failed
grep -q "AssertionError" stdouterr.txt
if [ "$?" == "0" ]; then
    exit 1
fi

# Check managed breakpoint was set
grep -q "Setting breakpoint: breakpoint set --address [0-9A-Fa-fx]* \[hello.Program.Main(System.String\[\])\]" stdouterr.txt
if [ "$?" != "0" ]; then
    exit 1
fi

# Check hello.Program.Main figures in clrstack
grep -q "[0-9A-Fa-f]* [0-9A-Fa-f]* hello.Program.Main(System.String\[\])" stdouterr.txt
if [ "$?" != "0" ]; then
    exit 1
fi

# Check clrstack at Debugger.Break()
grep -q "[0-9A-Fa-f]* [0-9A-Fa-f]* \[HelperMethodFrame: [0-9A-Fa-f]*\] System.Diagnostics.Debugger.BreakInternal()" stdouterr.txt
if [ "$?" != "0" ]; then
    exit 1
fi