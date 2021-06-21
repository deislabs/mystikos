TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = arch_prctl
APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

OPTS =
ifdef STRACE
OPTS += --strace
endif

all:
	$(MAKE) rootfs

rootfs: $(PROGRAM).c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/$(PROGRAM) $(PROGRAM).c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROGRAM)

clean:
	rm -rf $(APPDIR) rootfs export ramfs
