TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef TRACE
	OPTS += --strace --etrace
else
	ifdef STRACE
		OPTS += --strace
	endif
	ifdef ETRACE
		OPTS += --etrace
	endif
endif

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: signal.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/signal signal.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

tests: rootfs
	$(RUNTEST) $(MYST_EXEC) rootfs /signal $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
