.PHONY: tests
TOP=$(abspath ../..)
include $(TOP)/defs.mak

APPDIR=$(CURDIR)/appdir

# select lines from tests without '#' in the first column
TESTS=$(shell grep -v "^\#" tests)
ALL=$(shell grep -v "^\#" all)

ifndef ROOTFS
ROOTFS=rootfs
endif

ifdef TEST
SYSCALLS=/ltp/testcases/kernel/syscalls
test:
	./clean_hostfs.sh
	$(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST) $(NL)
endif

all: rootfs

rootfs: appdir
	sudo $(MYST) mkext2 appdir rootfs
	sudo chown $(USER).$(USER) rootfs
	truncate --size=-4096 rootfs

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
ifeq ($(ROOTFS),hostfs)
	rm -rf hostfs
	cp -r appdir hostfs
endif
	$(foreach i, $(TESTS), ( ./clean_hostfs.sh; $(RUNTEST) $(MYST_EXEC) $(ROOTFS) $(i) $(OPTS) ) $(NL) )

all-tests:
	- $(foreach i, $(ALL), $(RUNTEST) $(MYST_EXEC) rootfs $(i) $(OPTS) && echo $(i) >> ALL $(NL) )

clean:
	sudo rm -rf $(APPDIR) rootfs appdir

CACHEDIR=$(HOME)/.mystikos/cache/ltp

cache:
	rm -rf $(CACHEDIR)
	mkdir -p $(CACHEDIR)
	cp ./rootfs $(CACHEDIR)/rootfs

fetch:
	cp $(CACHEDIR)/rootfs ./rootfs

find:
	find appdir/ltp/testcases/kernel/syscalls -type f -executable -print

t:
	make TEST=/ltp/testcases/kernel/syscalls/creat/creat01 TARGET=linux
