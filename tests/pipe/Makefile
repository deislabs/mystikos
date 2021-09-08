TOP=$(abspath ../..)
include $(TOP)/defs.mak

CFLAGS = -Wall -g -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
APPDIR = $(SUBOBJDIR)/appdir

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: pipe.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/pipe pipe.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

ifdef STRACE
OPTS += --strace
endif

tests:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/pipe $(COUNT)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs

t: tests
