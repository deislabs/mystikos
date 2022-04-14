TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -lrt
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
PROG=map-shared
ifdef STRACE
OPTS += --strace
endif

OPTS += --nobrk --fork-mode pseudo_wait_for_exit_exec

all: myst rootfs

rootfs: $(PROG).c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(PROG) $(PROG).c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) empty-file
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) basic
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) share
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) restricted-mremap
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) restricted-mprotect
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) partial-ops-unsupported


TEST=basic
one:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) $(TEST)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs /bin/$(PROG) $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

build-native:
	gcc -o $(PROG) -g $(PROG).c -lrt

run-native:
	./$(PROG) $(TEST)
