TOP = $(abspath ../..)
SUBDIR = samples/libc-test
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

STRACE=1
ifdef STRACE
OPTS = --strace
endif

all: srcdir build

srcdir:
	cp -r $(TOP)/third_party/libc-test srcdir

build:
	sudo docker run --rm -v $(CURDIR)/srcdir:/srcdir $(IMG) bash -c "make -C srcdir"

TESTS = $(shell cat supported.txt)

tests:
	$(foreach i, $(TESTS), $(MAKE) run TEST=$(i) $(NL) )

run:
	@ echo "=== TEST=$(TEST)"
	@ rm -rf appdir
	@ mkdir -p appdir/src/functional
	@ install -D srcdir/$(TEST) appdir/$(TEST)
	@ cp srcdir/src/functional/*.so appdir/src/functional
	$(BINDIR)/libos mkcpio appdir rootfs
	$(BINDIR)/libos exec --real-syscalls $(OPTS) rootfs $(TEST)

clean:
	rm -rf rootfs appdir srcdir
