.NOTPARALLEL:
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef STRACE
OPTS += --strace
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs

TESTS=$(shell comm -23 tests.passed tests.remove)

ifdef MYST_ENABLE_GCOV
TESTS=$(shell comm -23 tests.passed tests.removegcov)
endif

OPTS+=--app-config-path config.json

all: myst
	$(MAKE) $(APPDIR)
	$(MAKE) $(APPDIR)/bin/run
	$(MAKE) $(ROOTFS)

# this target is to be used for local builds only,
# a similar build is already compiled in the docker container linked here
glibc:
	git clone https://sourceware.org/git/glibc.git

build: glibc
	cd glibc && git checkout release/2.34/master && \
    mkdir build && cd build && \
	../configure --prefix=/usr --disable-werror --enable-static-pie && \
	make -j && \
	make check
	find . -type f -executable -print | grep 'test\|tst\|check' | grep -v .*.so > temp
	sort temp > tests.all

PWD=$(shell pwd)

$(APPDIR):
	# $(APPBUILDER) -m -i mystikos/glibc-test:0.1
	# todo: replace with pre-built image
	$(APPBUILDER) -m -i hullcritical/glibc-test:0.1
	cp $(CURDIR)/tests.passed $(APPDIR)

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(ROOTFS): run.c
	$(MYST) mkext2 $(APPDIR) $(ROOTFS)

one:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST) $(NL)

tests:
ifndef POSIX_SPAWN
	$(foreach i, $(TESTS), $(RUNTEST) $(MYST_EXEC) $(OPTS) $(ROOTFS) $(i) $(NL) )
else
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /bin/run /tests.passed
endif

myst:
	$(MAKE) -C $(TOP)/tools/myst

clean:
	rm -rf $(APPDIR) $(ROOTFS)

TEST=/glibc/build/math/test-tgmath3-asin
gdb:
	$(MYST_GDB) --args $(MYST_EXEC) $(OPTS) $(ROOTFS) $(TEST) $(NL)
