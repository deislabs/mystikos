TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: strace.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/strace strace.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

OPTS =

ifdef PERF
OPTS += --perf
endif

OPTS += --thread-stack-size=1048576

__TESTS=1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17
.PHONY: $(__TESTS)

tests: $(__TESTS)
	echo " === passed test strace"

$(__TESTS):
	$(MAKE) test$@

test1:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_invali $(OPTS) 2> test1.txt || $(RUNTEST) diff test1.txt 1test.expected.txt
	echo "=== test1 passed"

test2:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_mmap --strace-exclude-filter=SYS_ioctl $(OPTS) 2> test2.txt || $(RUNTEST) diff test2.txt 2test.expected.txt
	echo "=== test2 passed"

test3:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_close:SYS_open $(OPTS) 2> test3.txt
	cat test3.txt | grep "SYS_" > 1 && cat test3.txt | grep -E '(SYS_close|SYS_open)' > 2 && $(RUNTEST) diff 1 2
	echo "=== test3 passed"

test4:
	$(MYST_EXEC) rootfs /bin/strace --strace-exclude-filter 'SYS_open:SYS_close' $(OPTS) 2> test4.txt
	cat test4.txt | grep -vE '(SYS_open|SYS_close)' > 3 && $(RUNTEST) diff 3 test4.txt
	echo "=== test4 passed"

test5:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=file $(OPTS) 2> test5.txt
	cat test5.txt | grep "SYS_" > 4 && cat test5.txt | grep -E '(SYS_open|SYS_getcwd)' > 5 && $(RUNTEST) diff 4 5
	echo "=== test5 passed"

test6:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=file:desc:memory $(OPTS) 2> test6.txt
	cat test6.txt | grep "SYS_" > 6 && cat test6.txt | grep -E '(SYS_open|SYS_read|SYS_mmap|SYS_close|SYS_mprotect|SYS_getcwd)' > 7 && $(RUNTEST) diff 6 7
	echo "=== test6 passed"
	
test7:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=file:SYS_mmap $(OPTS) 2> test7.txt
	cat test7.txt | grep "SYS_" > 8 && cat test7.txt | grep -E '(SYS_open|SYS_getcwd|SYS_mmap)' > 9 && $(RUNTEST) diff 8 9
	echo "=== test7 passed"

test8:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=fil:SYS_maa $(OPTS) 2> test8.txt || $(RUNTEST) diff test8.txt 8test.expected.txt
	echo "=== test8 passed"

test9:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=file --strace-exclude-filter=SYS_mmap $(OPTS) 2> test9.txt || $(RUNTEST) diff test9.txt 2test.expected.txt
	echo "=== test9 passed"

test10:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter-tid=file $(OPTS) 2> test10.txt || $(RUNTEST) diff test10.txt 10test.expected.txt
	echo "=== test10 passed"

test11:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter-tid=101 $(OPTS) 2> test11.txt
	test ! -s test11.txt || cat test11.txt | grep "tid=" > 10 && cat test11.txt | grep 'tid=101' > 11 && $(RUNTEST) diff 10 11
	echo "=== test11 passed"

test12:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_mmap --strace-filter-tid 101 $(OPTS) 2> test12.txt
	test ! -s test12.txt || cat test12.txt | grep -E '(tid=|SYS_)' > 13 && cat test12.txt | grep -E '(tid=101|SYS_mmap)' > 14 && $(RUNTEST) diff 13 14
	echo  "=== test12 passed"

test13:
	$(MYST_EXEC) rootfs /bin/strace --strace-exclude-filter=SYS_mmap --strace-filter-tid 101 $(OPTS) 2> test13.txt
	test ! -s test13.txt || cat test13.txt | grep -E '(tid=|SYS_)' > 15 && cat test13.txt | grep 'tid=101' | grep -v 'SYS_mmap' > 16 && $(RUNTEST) diff 15 16
	echo  "=== test13 passed"

test14:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter-pid=file $(OPTS) 2> test14.txt || $(RUNTEST) diff test14.txt 10test.expected.txt
	echo "=== test14 passed"

test15:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter-pid=101 $(OPTS) 2> test15.txt
	test ! -s test15.txt || cat test15.txt | grep "pid=" > 17 && cat test15.txt | grep 'pid=101' > 18 && $(RUNTEST) diff 17 18
	echo "=== test15 passed"

test16:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_mmap --strace-filter-pid 101 $(OPTS) 2> test16.txt
	test ! -s test16.txt || cat test16.txt | grep -E '(pid=|SYS_)' > 19 && cat test16.txt | grep -E '(pid=101|SYS_mmap)' > 20 && $(RUNTEST) diff 19 20
	echo  "=== test16 passed"

test17:
	$(MYST_EXEC) rootfs /bin/strace --strace-exclude-filter=SYS_mmap --strace-filter-pid 101 $(OPTS) 2> test17.txt
	test ! -s test17.txt || cat test17.txt | grep -E '(pid=|SYS_)' > 21 && cat test17.txt | grep 'pid=101' | grep -v 'SYS_mmap' > 22 && $(RUNTEST) diff 21 22
	echo  "=== test17 passed"

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs 1 2 3 test1.txt text2.txt test3.txt test4.txt
