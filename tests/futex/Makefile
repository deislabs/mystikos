TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

all:
	$(MAKE) myst
	$(MAKE) rootfs

rootfs: futex.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/futex futex.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

OPTS =

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

OPTS += --user-mem-size=16m

tests: all
	$(MAKE) test1
	$(MAKE) test2

test1:
	gcc -Wall -o futex futex.c -lpthread
	$(RUNTEST) ./futex $(COUNT)

test2:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/futex $(OPTS) $(COUNT)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs futex

stress:
	$(MAKE) COUNT=100 test2
