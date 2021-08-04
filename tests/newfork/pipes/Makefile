TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -Wall -Werror
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: pipes.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/pipes pipes.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=32m

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/pipes $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

t:
	$(MAKE) tests STRACE=1

nc:
	nc -U $(wildcard /tmp/myst*.socket)
