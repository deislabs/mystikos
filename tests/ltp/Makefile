.PHONY: tests
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

ifdef STRACE
OPTS += --strace
endif

ifdef ETRACE
OPTS += --etrace
endif

ifdef TRACE
OPTS += --etrace --strace
endif

ifndef FS
FS=ext2fs
endif

ifeq ($(FS),hostfs)
# select lines from tests without '#' in the first column
ifndef MYST_NIGHTLY_TEST
TESTS=$(shell grep -v "^\#" hostfs_tests_passed.txt)
else
TESTS=$(shell grep -v "^\#" hostfs_fs_tests_passed.txt)
endif
FOUND=1
endif

ifeq ($(FS),ext2fs)
# select lines from tests without '#' in the first column
ifndef MYST_NIGHTLY_TEST
TESTS=$(shell grep -v "^\#" ext2fs_tests_passed.txt)
else
TESTS=$(shell grep -v "^\#" ext2fs_fs_tests_passed.txt)
endif
FOUND=1
endif

ifeq ($(FS),ramfs)
# select lines from tests without '#' in the first column
ifndef MYST_NIGHTLY_TEST
TESTS=$(shell grep -v "^\#" ramfs_tests_passed.txt)
else
TESTS=$(shell grep -v "^\#" ramfs_fs_tests_passed.txt)
endif
FOUND=1
endif

ifeq ($(FOUND),)
$(error "bad value for FS: must be hostfs or ext2fs")
endif

# overlayfs directories
LOWERDIR=$(CURDIR)/appdir
UPPERDIR=$(CURDIR)/upper
WORKDIR=$(CURDIR)/work
HOSTFS=$(CURDIR)/hostfs

all: ext2fs

ext2fs: appdir
	sudo $(MYST) mkext2 --force appdir ext2fs
	truncate --size=-4096 ext2fs

URL=https://github.com/mikbras/ltp

appdir:
	$(MAKE) clone
	$(MAKE) build

build:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak"
	sudo chown -R $(USER).$(USER) appdir
	$(MAKE) password-file
	$(MAKE) group-file

rebuild:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak build"
	sudo chown -R $(USER).$(USER) appdir
	$(MAKE) password-file
	$(MAKE) group-file

clone:
	rm -rf appdir
	mkdir appdir
	git clone https://github.com/mikbras/ltp appdir/ltp -b myst

password-file:
	mkdir -p appdir/etc
	echo "root:x:0:0:root:/root:/bin/bash" > appdir/etc/passwd
	echo "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" >> appdir/etc/passwd
	echo "bin:x:2:2:bin:/bin:/usr/sbin/nologin" >> appdir/etc/passwd
	echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologi" >> appdir/etc/passwd

group-file:
	mkdir -p appdir/etc
	echo "root:x:0:" > appdir/etc/group
	echo "daemon:x:1:" >> appdir/etc/group
	echo "bin:x:2:" >> appdir/etc/group
	echo "nogroup:x:65534" >> appdir/etc/group
	echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" >> appdir/etc/group

tests:
	$(MAKE) tests_hostfs
	$(MAKE) tests_ext2fs
	$(MAKE) tests_ramfs

tests_hostfs:
	$(MAKE) alltests FS=hostfs

tests_ext2fs:
	$(MAKE) alltests FS=ext2fs

tests_ramfs:
	$(MAKE) alltests FS=ramfs

alltests:
	$(foreach i, $(TESTS), $(MAKE) one FS=$(FS) TEST=$(i) $(NL) )

clean:
	sudo rm -rf $(APPDIR) ext2fs appdir $(UPPERDIR) $(WORKDIR) $(HOSTFS)

CACHEDIR=$(HOME)/.mystikos/cache/ltp

cache:
	rm -rf $(CACHEDIR)
	mkdir -p $(CACHEDIR)
	cp -r ./appdir $(CACHEDIR)/appdir

fetch:
	cp -r $(CACHEDIR)/appdir ./appdir

find:
	find appdir/ltp/testcases/kernel/syscalls -type f -executable -print

sort:
	sort tests | uniq > .tests
	cp .tests tests
	rm -f .tests

##==============================================================================
##
## one rule for ext2fs
##
##==============================================================================

ifeq ($(FS),ext2fs)
one:
	sudo -E $(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

##==============================================================================
##
## one rule for hostfs
##
##==============================================================================

ifeq ($(FS),hostfs)
one:
	@ sudo rm -rf $(HOSTFS)
	@ mkdir -p $(shell dirname $(HOSTFS)/$(TEST))
	cp appdir/$(TEST) $(HOSTFS)/$(TEST)
	cp -r appdir/etc $(HOSTFS)/
	sudo -E $(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

##==============================================================================
##
## one rule for ramfs
##
##==============================================================================

ifeq ($(FS),ramfs)
one:
	sudo rm -rf ramfs.appdir
	mkdir -p $(shell dirname ramfs.appdir/$(TEST))
	cp appdir/$(TEST) ramfs.appdir/$(TEST)
	cp -r appdir/etc  ramfs.appdir/
	$(MYST) mkcpio ramfs.appdir ramfs
	sudo -E $(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

