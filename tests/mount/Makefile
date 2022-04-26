TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = mount

SOURCES = mount.c

INCLUDES =

CFLAGS = -Wall -fPIC -g

ifdef MYST_ENABLE_GCOV
CFLAGS += $(GCOV_CFLAGS)
endif

ifdef STRACE
OPTS += --strace
endif

CLEAN = appdir rootfs ramfs

include $(TOP)/rules.mak

build-extra:
	rm -rf appdir
	rm -rf rootfs ramfs ext2fs

	# Create ramfs
	$(MKROOTFS) $(SUBBINDIR)/mount rootfs
	$(MYST) excpio rootfs appdir
	# Can only mount ramfs that are located INSIDE enclave
	$(MYST) mkcpio datafs appdir/ramfs
	# Can only mount ext2fs that are located OUTSIDE enclave
	$(MYST) mkext2 datafs ext2fs

	# Make mounting point in rootfs
	mkdir -p appdir/mnt/datafs
	mkdir -p appdir/mnt/hostfs
	mkdir -p appdir/mnt/ramfs
	mkdir -p appdir/mnt/ext2fs

	# Create rootfs
	sudo chown -R $(USER).$(USER) appdir
	$(MYST) mkcpio appdir rootfs

tests-hostfs:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/mount hostfs --app-config-path config-hostfs.json --mount $(CURDIR)/datafs=/mnt/hostfs

tests-ramfs:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/mount ramfs --app-config-path config-ramfs.json --mount /ramfs=/mnt/ramfs

tests-ext2fs:
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/mount ext2fs --app-config-path config-ext2fs.json --mount $(CURDIR)/ext2fs=/mnt/ext2fs

tests: build-extra
	$(MAKE) tests-hostfs
	$(MAKE) tests-ramfs
	$(MAKE) tests-ext2fs

gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) rootfs /bin/mount ext2fs --app-config-path config-ext2fs.json --mount /ext2fs=/mnt/ext2fs
