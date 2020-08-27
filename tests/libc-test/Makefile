TOP = $(abspath ../..)
SUBDIR = samples/libc-test
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

all: rootfs

rootfs: appdir build
	$(BINDIR)/libos mkcpio appdir rootfs

appdir:
	cp -r $(TOP)/third_party/libc-test appdir

build:
	sudo docker run --rm -v $(APPDIR):/appdir $(IMG) bash -c "make -C appdir"

TESTS = $(shell cat supported.txt)

tests:
	$(foreach i, $(TESTS), $(MAKE) run TEST=$(i) $(NL) )

#OPTS = --strace

run:
	$(BINDIR)/libos exec $(OPTS) rootfs $(TEST)

clean:
	rm -rf rootfs appdir
