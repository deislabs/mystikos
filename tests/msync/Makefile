TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

TARGET2=$(SUBOBJDIR)/msync

all:
	$(MAKE) myst
	$(MAKE) $(TARGET2)
	$(MAKE) rootfs

rootfs: msync.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/msync msync.c $(LDFLAGS)
	$(MYST) mkcpio $(APPDIR) rootfs

$(TARGET2): msync.c
	mkdir -p $(SUBOBJDIR)
	$(CC) $(CFLAGS) msync.c -o $(TARGET2)

ifdef STRACE
OPTS = --strace
endif

tests: test1 test2

test1:
	$(RUNTEST) $(MYST_EXEC) rootfs /bin/msync $(OPTS)

test2:
	$(TARGET2)

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) rootfs export ramfs $(TARGET2)
