TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROG=cross_fs_symlinks
APPDIR = appdir
CFLAGS = -fPIC
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)
ROOTHASH=roothash
ifdef STRACE
OPTS = --strace
endif

all:
	$(MAKE) $(APPDIR)

tests: test_ramfs_rootfs test_ext2_rootfs

test_ramfs_rootfs: rootfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) rootfs /bin/$(PROG) ramfs

test_ext2_rootfs: ext2rootfs
ifdef MYST_ENABLE_EXT2FS
	$(MYST) fssig --roothash ext2rootfs > $(ROOTHASH)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) \
	ext2rootfs --roothash=$(ROOTHASH) /bin/$(PROG) ext2
endif

$(APPDIR):
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -g -o $(APPDIR)/bin/cross_fs_symlinks cross_fs_symlinks.c $(LDFLAGS)
	# Create CPIO in appdir, which will be mounted later by the program 
	mkdir cpio_image && $(MYST) mkcpio cpio_image $(APPDIR)/cpio_image

rootfs: $(APPDIR)
	$(MYST) mkcpio $(APPDIR) rootfs

ext2rootfs: $(APPDIR)
	sudo $(MYST) mkext2 --force $(APPDIR) ext2rootfs

clean:
	rm -rf $(APPDIR) rootfs ramfs cpio_image ext2rootfs roothash
