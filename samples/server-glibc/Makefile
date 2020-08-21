SUBDIR = samples/main
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir
LIBOS = $(BINDIR)/libos
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
CC = /usr/bin/gcc

all: libos
	mkdir -p $(APPDIR)/bin
	$(CC) $(CFLAGS) -o $(APPDIR)/bin/main main.c $(LDFLAGS)
	$(LIBOS) mkcpio $(APPDIR) rootfs

#OPTS = --trace-syscalls

run: all
	$(LIBOS) exec rootfs /bin/main $(OPTS)

libos:
	$(MAKE) -C $(TOP)/tools/libos

clean:
	rm -rf $(APPDIR) rootfs
