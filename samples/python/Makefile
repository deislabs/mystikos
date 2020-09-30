TOP = $(abspath ../..)
include $(TOP)/defs.mak

all:

ifdef STRACE
OPTS = --strace
endif

run:
	$(MKROOTFS) python3 rootfs hello_world.py
	rm -rf appdir
	$(LIBOS) excpio rootfs appdir
	mkdir -p appdir/usr/lib
	$(LIBOS) mkcpio appdir rootfs
	$(LIBOS_EXEC) $(OPTS) rootfs /bin/python3 /hello_world.py --strace

clean:
	rm -rf rootfs hello_world appdir
