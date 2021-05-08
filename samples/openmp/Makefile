TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
# OPTS = --strace
endif

all: appdir rootfs

appdir:
	$(APPBUILDER) Dockerfile

rootfs: appdir
	sudo $(MYST) mkext2 appdir ext2rootfs
	sudo chown $(USER).$(USER) ext2rootfs
	$(MYST) fssig --roothash ext2rootfs > roothash
	# $(MYST) mkcpio appdir rootfs

run:
	$(MYST_EXEC) $(OPTS) --roothash=roothash ext2rootfs /app/openmp-test

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) --roothash=roothash ext2rootfs /app/openmp-test

clean:
	rm -rf rootfs ext2rootfs appdir roothash
