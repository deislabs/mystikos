.PHONY: ext2fs
.PHONY: tests
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

ifndef FS
FS=ext2fs
endif

ifeq ($(FS),hostfs)
FOUND=1
endif

ifeq ($(FS),ext2fs)
FOUND=1
endif

ifeq ($(FOUND),)
$(error "bad value for FS: must be hostfs or ext2fs")
endif

# select lines from tests without '#' in the first column
TESTS=$(shell grep -v "^\#" tests)

# overlayfs directories
LOWERDIR=$(CURDIR)/appdir
UPPERDIR=$(CURDIR)/upper
WORKDIR=$(CURDIR)/work
HOSTFS=$(CURDIR)/hostfs

ifdef STRACE
OPTS = --strace
endif

OPTS += --user-mem-size=16m

ifdef TEST
test:
ifeq ($(FS),hostfs)
	- @ sudo umount $(HOSTFS)
	@ rm -rf $(UPPERDIR) $(WORKDIR) $(HOSTFS)
	@ mkdir -p $(UPPERDIR) $(WORKDIR) $(HOSTFS)
	@ sudo mount -t overlay overlay -o lowerdir=$(LOWERDIR),upperdir=$(UPPERDIR),workdir=$(WORKDIR) $(HOSTFS)
endif
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
ifeq ($(FS),hostfs)
	- @ sudo umount $(HOSTFS)
endif
endif

all: ext2fs

ext2fs: appdir
	sudo $(MYST) mkext2 appdir ext2fs
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

tests:
	$(foreach i, $(TESTS), $(MAKE) TEST=$(i) $(NL) )

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
