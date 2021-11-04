TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -Wno-discarded-qualifiers
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
PROG = test_sys_execve

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=16m

# The id of test to run, 0 based index
ARG=

build: rootfs

appdir: clean
	@mkdir -p $(APPDIR)/bin
	@mkdir -p $(APPDIR)/symlink

	$(MUSL_GCC) $(CFLAGS) src/echo.c -o $(APPDIR)/bin/echo $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) src/$(PROG).c -o $(APPDIR)/$(PROG) $(LDFLAGS)

rootfs: appdir
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	for number in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 ; do \
		$(RUNTEST) $(MAKE) single ARG=$$number ; \
	done

	@echo "=== passed test $(PROG)"

single:
	$(MYST_EXEC) $(OPTS) rootfs /$(PROG) $(ARG)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /$(PROG) $(ARG)

clean:
	rm -rf appdir rootfs

# For local testing

# Build to run outside Mystikos
local: clean
	@mkdir -p $(APPDIR)/bin
	gcc $(CFLAGS) src/echo.c -o $(APPDIR)/bin/echo
	gcc $(CFLAGS) src/test_sys_execve.c -o $(APPDIR)/$(PROG)
