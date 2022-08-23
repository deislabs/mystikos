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

tests: all test1 test2 test3 test4
	echo " === passed test strace"

test1:
	-$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_invali $(OPTS) 2> test1.txt || $(RUNTEST) diff test1.txt test1.expected.txt
	echo "=== test1 passed"

test2:
	-$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_mmap --strace-exclude-filter=SYS_ioctl $(OPTS) 2> test2.txt || $(RUNTEST) diff test2.txt test2.expected.txt
	echo "=== test2 passed"

test3:
	$(MYST_EXEC) rootfs /bin/strace --strace-filter=SYS_close:SYS_open $(OPTS) 2> test3.txt
	cat test3.txt | grep "SYS_" > 1 && cat test3.txt | grep -E '(SYS_close|SYS_open)' > 2 && $(RUNTEST) diff 1 2
	echo "=== test3 passed"

test4:
	$(MYST_EXEC) rootfs /bin/strace --strace-exclude-filter 'SYS_open:SYS_close' $(OPTS) 2> test4.txt
	cat test4.txt | grep -v "SYS_open" > 3 && $(RUNTEST) diff 3 test4.txt
	cat test4.txt | grep -v "SYS_close" > 3 && $(RUNTEST) diff 3 test4.txt
	echo "=== test4 passed"

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs 1 2 3 test1.txt text2.txt test3.txt test4.txt
