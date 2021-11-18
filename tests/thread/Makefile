TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
CC = $(MUSL_GCC)

OPTS = --thread-stack-size=1m

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: thread.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/thread thread.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/thread

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs
