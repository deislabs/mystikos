TOP = $(abspath ../..)
include $(TOP)/defs.mak

ifeq (, $(shell which rustc))
 $(error "Please install rustc first!")
endif

all:
	rustc ./hello_world.rs

ifdef STRACE
OPTS = --strace
endif

run:
	$(MKROOTFS) ./hello_world rootfs
	$(MYST_EXEC) $(OPTS) rootfs /bin/hello_world

clean:
	rm -rf rootfs hello_world
