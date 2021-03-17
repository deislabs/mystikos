.PHONY: ext2fs
.PHONY: tests
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

ifndef FS
FS=ext2fs
endif

ifeq ($(FS),hostfs)
# select lines from tests without '#' in the first column
TESTS=$(shell grep -v "^\#" hostfs_tests_passed.txt)
FOUND=1
endif

ifeq ($(FS),ext2fs)
# select lines from tests without '#' in the first column
TESTS=$(shell grep -v "^\#" ext2fs_tests_passed.txt)
FOUND=1
endif

ifeq ($(FS),ramfs)
# select lines from tests without '#' in the first column
TESTS=$(shell grep -v "^\#" ramfs_tests_passed.txt)
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
	sudo chown $(USER).$(USER) ext2fs
	truncate --size=-4096 ext2fs

URL=https://github.com/mikbras/ltp

appdir:
	$(MAKE) clone
	$(MAKE) build

build:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak"
	sudo chown -R $(USER).$(USER) appdir

rebuild:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak build"
	sudo chown -R $(USER).$(USER) appdir

clone:
	rm -rf appdir
	mkdir appdir
	git clone https://github.com/mikbras/ltp appdir/ltp -b myst

ifdef STRACE
OPTS = --strace
endif

tests:
	$(MAKE) alltests FS=hostfs  
	$(MAKE) alltests FS=ext2fs
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
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

##==============================================================================
##
## one rule for hostfs
##
##==============================================================================

ifeq ($(FS),hostfs)
one:
	@ $(MAKE) -s umount
	@ rm -rf $(UPPERDIR) $(WORKDIR) $(HOSTFS)
	@ mkdir -p $(UPPERDIR) $(WORKDIR) $(HOSTFS)
	@ sudo mount -t overlay overlay -o lowerdir=$(LOWERDIR),upperdir=$(UPPERDIR),workdir=$(WORKDIR) $(HOSTFS)
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
	@ $(MAKE) -s umount

umount:
	- @ sudo umount $(HOSTFS) 2> /dev/null
endif

##==============================================================================
##
## one rule for ramfs
##
##==============================================================================

ifeq ($(FS),ramfs)
one:
	rm -rf ramfs.appdir
	mkdir -p $(shell dirname ramfs.appdir/$(TEST))
	cp appdir/$(TEST) ramfs.appdir/$(TEST)
	$(MYST) mkcpio ramfs.appdir ramfs
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

t:
	make one FS=ramfs TEST=/ltp/testcases/kernel/syscalls/llseek/llseek03
