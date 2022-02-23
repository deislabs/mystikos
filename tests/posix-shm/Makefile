TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g -lrt
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS += --strace
endif

OPTS += --nobrk --fork-mode pseudo_wait_for_exit_exec

all: myst rootfs

rootfs: shm-fun.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/shm-fun shm-fun.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun empty-file
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun basic
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun share
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun resize-backing-file
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun resize-memory
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun offset-tests


TEST=basic
one:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/shm-fun $(TEST)

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs /bin/shm-fun $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

build-native:
	gcc -o shm-fun -g shm-fun.c -lrt

run-native:
	./shm-fun $(TEST)
