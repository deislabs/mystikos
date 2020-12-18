#!/bin/bash

test_directory="/ltp/testcases/kernel/syscalls"
cd /
touch .c_binaries_list

cd /ltp
c_binaries_list_file_tmp="/ltp/.c_binaries_list.tmp"
c_binaries_list_file="/ltp/.c_binaries_list"
rm -rf $c_binaries_list_file
touch $c_binaries_list_file

echo "Running make clean..."
make autotools
./configure
make clean > /dev/null 2> /dev/null
    
pass_file="/ltp/passed_test.txt"
fail_file="/ltp/failed_test.txt"
echo "" > $pass_file
echo "" > $fail_file

IFS=$'\n'
file_list=( $(find $test_directory -name Makefile) )

makefile_counter=$(find $test_directory -name Makefile | wc -l)
counter=0
c_binaries_counter=0
c_binaries_failures=0

echo "Compling and generating binaries in $test_directory recursively"
for file in ${file_list[@]};
do
    current_test_directory=$(dirname $file)
    counter=$(($counter + 1))
    printf '%-17s' "[Test #$counter/$makefile_counter]"
    cd $current_test_directory
    c_file_list=( $(find . -name "*.c") )
    printf '%-70s' "Building $current_test_directory "
    make 1> build.log 2>&1
    if [[ $? == 0 ]]; then
            printf '%-10s\n' "Success"
            for c_file in ${c_file_list[@]};
            do
                    filename="${c_file%.*}"
                    if [ -f $filename ];then
                        c_binaries_counter=$(($c_binaries_counter + 1))
                        echo "$current_test_directory/$filename" >> $c_binaries_list_file_tmp
                    else
                        echo -e "\t \t WARNING !! $filename is not generated"
                    fi
            done
    else
            printf '%-10s\n' "Failed"
            echo "_________________________________________"
            cat build.log
            echo -e "_________________________________________\n"
            c_binaries_failures=$(($c_binaries_failures + 1))
    fi
    [ -f build.log ] && rm -f build.log
    cd /ltp
done
sed 's/\.\///' -i $c_binaries_list_file_tmp
cat $c_binaries_list_file_tmp | sort | uniq  > $c_binaries_list_file
rm -f $c_binaries_list_file_tmp
echo "--------------------------------------------------------------"
echo "Generated $c_binaries_counter binaries in $test_directory"
echo $c_binaries_counter > .c_binaries_counter
echo "Failed to generate $c_binaries_failures binaries in $test_directory"
echo "--------------------------------------------------------------"
