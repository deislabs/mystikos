TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
FS=mkcpio

OPTS=
ifdef STRACE
OPTS = --strace
endif

all:
	$(MAKE) rootfs

rootfs: main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/main main.c $(LDFLAGS)
	$(MYST) $(FS) $(APPDIR) rootfs

TEST_SINGLE = $(MYST_EXEC) rootfs $(OPTS) --app-config-path config.json /bin/main
test-basic:
	$(TEST_SINGLE) basic

test-empty-file:
	$(TEST_SINGLE) empty-file

test-share:
	$(TEST_SINGLE) share

test-duplicate:
	$(TEST_SINGLE) duplicate

test-cloexec:
	$(TEST_SINGLE) cloexec

test-proc:
	$(TEST_SINGLE) proc

tests:
	make test-basic
	make test-empty-file
	make test-share
	make test-duplicate
	make test-cloexec
	# make test-proc # Disable for now as not supported

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs --app-config-path config.json /bin/main $(OPTS)

local: main.c
	rm -f ./main
	gcc -g -o ./main main.c -lrt
	./main basic

clean:
	rm -rf $(APPDIR) rootfs main
