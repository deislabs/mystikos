TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC -Wall -Werror
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: newfork.c hello.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/newfork newfork.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/hello hello.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/goodbye goodbye.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

#OPTS += --memory-size=8m
#OPTS += --memory-size=512m

tests: all
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/newfork $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

t:
	$(MAKE) tests STRACE=1
