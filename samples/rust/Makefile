TOP = $(abspath ../..)
include $(TOP)/defs.mak

all:
	rustc ./hello_world.rs

ifdef STRACE
OPTS = --strace
endif

run:
	$(MKROOTFS) ./hello_world rootfs
	$(LIBOS_EXEC) $(OPTS) rootfs /bin/hello_world

clean:
	rm -rf rootfs hello_world
