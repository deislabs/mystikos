# Running this script gives us an idea of which cpp tests build on ubuntu

# make llvm-project
# make libcxx-tests

LIBCXX_TESTS_DIR=llvm-project/libcxx/test/

START=$(pwd)
cd $LIBCXX_TESTS_DIR
TEST_DIR=$(pwd)
find . -type d > dirs.txt

for dir in $(cat dirs.txt); \
do cd $dir && echo $dir; \
for f in $(ls | grep pass.cpp); \
    do echo $f && g++ -g -I$TEST_DIR/support -fPIC -Wall -o $( basename ${f}.exe) $f; \
    done; \
cd $TEST_DIR ; \
done;

cd $START/libcxx-tests
find $LIBCXX_TESTS_DIR -name \*pass.cpp.exe > builttests_exe.txt
sed -i -e 's/^/\/app\//' builttests_exe.txt