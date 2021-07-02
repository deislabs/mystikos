TOP=$(abspath ../../..)
include $(TOP)/defs.mak

APPDIR = $(SUBOBJDIR)/appdir
ROOTFS = $(SUBOBJDIR)/rootfs
RAMFSDIR = $(SUBOBJDIR)/ramfsdir
RAMFS = $(APPDIR)/ramfs
EXT2FSDIR = $(SUBOBJDIR)/ext2fsdir
EXT2FS = $(SUBOBJDIR)/ext2
EXT2FS_SIZE=134217728
HOSTFSDIR = $(SUBOBJDIR)/hostfsdir
HOSTFSDIR3 = $(SUBOBJDIR)/hostfsdir3
CFLAGS = -fPIC -g
LDFLAGS = -Wl,-rpath=$(MUSL_LIB)

ifdef STRACE
OPTS = --strace
endif

all: rootfs ramfs ext2fs hostfs

build:	main.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) $(CFLAGS) -o $(APPDIR)/bin/test main.c $(LDFLAGS)

rootfs: build ramfs
	mkdir -p $(APPDIR)/ramfs-target
	mkdir -p $(APPDIR)/ext2-target
	mkdir -p $(APPDIR)/hostfs-target
	$(MYST) mkcpio $(APPDIR) $(ROOTFS)
	$(MYST) mkext2 --force $(APPDIR) ext2rootfs

ramfs:
	mkdir -p $(RAMFSDIR)
	mkdir -p $(APPDIR)
	touch $(RAMFSDIR)/ramfs-file
	$(MYST) mkcpio $(RAMFSDIR) $(RAMFS)

ext2fs:
	mkdir -p $(EXT2FSDIR)
	touch $(EXT2FSDIR)/ext2-file
	$(MYST) mkext2 --force --size=$(EXT2FS_SIZE) $(EXT2FSDIR) $(EXT2FS) 

hostfs:
	mkdir -p $(HOSTFSDIR)
	mkdir -p $(HOSTFSDIR3)
	touch $(HOSTFSDIR)/hostfs-file
	touch $(HOSTFSDIR3)/testfile1
	touch $(HOSTFSDIR3)/testfile2

# This updates the config file with the roothash.
# currently not in use until the processing of the roothash is updated within the kernel
update-config: ramfs ext2fs hostfs
	$(MYST) fssig --roothash $(EXT2FS) > roothash
	cat config1.json | sed 's/MOUNTEXT2ROOTHASH/$(shell cat roothash)/g' > config.json
	rm -f roothash

tests:
	$(MAKE) test-auto-mount test-auto-mount-ext2rootfs

test-auto-mount: rootfs ext2fs hostfs
	$(RUNTEST) $(MYST_EXEC) $(ROOTFS) $(OPTS) --mount /ramfs=/ramfs-target --mount $(EXT2FS)=/ext2-target --mount $(HOSTFSDIR)=/hostfs-target \
	--mount $(HOSTFSDIR3)/testfile1=/targetfile1 --mount $(HOSTFSDIR3)/testfile2=/targetfile2 --app-config-path config1.json /bin/test test1

test-auto-mount-ext2rootfs: rootfs ext2fs hostfs
	$(RUNTEST) $(MYST_EXEC) ext2rootfs $(OPTS) --mount /ramfs=/ramfs-target --mount $(EXT2FS)=/ext2-target --mount $(HOSTFSDIR)=/hostfs-target \
	--mount $(HOSTFSDIR3)/testfile1=/targetfile1 --mount $(HOSTFSDIR3)/testfile2=/targetfile2 --app-config-path config1.json /bin/test test1

gdb: rootfs ext2fs hostfs
	$(MYST_GDB) --args $(MYST_EXEC) $(ROOTFS) $(OPTS) --mount /ramfs=/ramfs-target --mount $(EXT2FS)=/ext2-target --mount $(HOSTFSDIR)=/hostfs-target \
	--mount $(HOSTFSDIR3)/testfile1=/targetfile1 --mount $(HOSTFSDIR3)/testfile2=/targetfile2 --app-config-path config1.json /bin/test test1

clean:
	sudo rm -rf $(APPDIR) $(RAMFSDIR) $(EXT2FSDIR) $(HOSTFSDIR) $(HOSTFSDIR3) $(RAMFS) $(EXT2FS) $(ROOTFS) sig-info config.json
