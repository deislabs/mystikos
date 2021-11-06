TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -Wno-discarded-qualifiers 
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
PROG = test_sys_execve

ifdef STRACE
OPTS += --strace
endif

# The id of test to run, 0 based index
ARG=

build: rootfs

appdir: clean
	@mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) src/echo.c -o $(APPDIR)/bin/echo $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) src/test_sys_execve.c -o $(APPDIR)/$(PROG) $(LDFLAGS)

rootfs: appdir
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MAKE) single ARG=0
	$(RUNTEST) $(MAKE) single ARG=1
	$(RUNTEST) $(MAKE) single ARG=2
	$(RUNTEST) $(MAKE) single ARG=3
	$(RUNTEST) $(MAKE) single ARG=4
	$(RUNTEST) $(MAKE) single ARG=5
	@echo "=== passed test $(PROG)"

single:
	$(MYST_EXEC) $(OPTS) rootfs /$(PROG) $(ARG)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /$(PROG) $(ARG)

clean:
	rm -rf appdir rootfs
