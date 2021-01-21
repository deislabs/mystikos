TEST_LIST=$(cat pr0-tests-all)

idx=1
ret_val=-1
for file_dll in $TEST_LIST
do
	t0=$(date +"%T")
	echo "Running test $idx|$NUM_TESTS: $file_dll $t0"
	myst/bin/corerun \
     /coreclr-tests-all/$file_dll
    ret_val=$?
	rm -rf /tmp/myst*
	t1=$(date +"%T")
	echo "Exit code: $ret_val $t1"
	# Error code 100 represents success in dotnet runtime tests
	if [[ $ret_val == 100 ]]
	then
	    echo $file_dll >> PASSED
	else
	    echo $file_dll >> FAILED-$ret_val
	fi
	echo "***************************************"
	idx=$((idx+1))
done

