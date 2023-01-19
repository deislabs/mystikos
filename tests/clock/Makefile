TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef MYST_ENABLE_GCOV
CFLAGS += -DMYST_ENABLE_GCOV
endif

ifdef TRACE
	OPTS += --strace --ttrace
else
	ifdef STRACE
		OPTS += --strace
	else
		OPTS += --ttrace
	endif
endif

sec = $(shell date +%s)
nsec = $(shell date +%N)

all: myst
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -g -o $(APPDIR)/bin/clock main.c $(LDFLAGS)
	$(MUSL_GCC) $(CFLAGS) -g -o $(APPDIR)/bin/cpuclocks cpuclocks.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

OPTS += --memory-size=16m

tests:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/clock  $(sec) $(nsec) $(OPTS)
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/cpuclocks $(OPTS)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs ramfs

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) rootfs /bin/cpuclocks $(OPTS)
