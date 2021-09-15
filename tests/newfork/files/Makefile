TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -Wall -Werror
LDFLAGS = -Wl,-rpath=$(MUSL_LIB) -lpthread

all:
	$(MAKE) rootfs

rootfs: files.c
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/files files.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

OPTS += --memory-size=8m

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/files $(OPTS)

clean:
	rm -rf $(APPDIR) rootfs export ramfs
