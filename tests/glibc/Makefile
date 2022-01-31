.NOTPARALLEL:
TOP=$(abspath ../..)
include $(TOP)/defs.mak

ifdef TRACE
OPTS += --strace --etrace
else
ifdef STRACE
OPTS += --strace
endif
ifdef ETRACE
OPTS += --etrace
endif
endif

APPDIR=$(CURDIR)/appdir
APPBUILDER=$(TOP)/scripts/appbuilder

ROOTFS=$(CURDIR)/rootfs


ifdef MYST_ENABLE_GCOV
TESTS=$(shell comm -23 tests.passed tests.removegcov)
GLIBC_BUILD_TEST_LIST = $(shell comm -23 tests.passed tests.removegcov | sed 's/\/glibc\/build\///g')
else
TESTS=$(shell comm -23 tests.passed tests.remove)
GLIBC_BUILD_TEST_LIST = $(shell comm -23 tests.passed tests.remove | sed 's/\/glibc\/build\///g')
endif

OPTS+=--app-config-path config.json

all: myst
	$(MAKE) $(APPDIR)
	$(MAKE) $(APPDIR)/bin/run
	$(MAKE) $(ROOTFS)

# this target is to be used for local builds only,
# a similar build is already compiled in the docker container linked here
glibc:
	git clone --branch= release/2.34/master https://sourceware.org/git/glibc.git


GLIBC_BUILD_TEST_LIST = $(shell comm -23 tests.passed tests.remove | sed 's/\/glibc\/build\///g')

docker-run:
	

glibc/build/Makefile: glibc
	mkdir -p glibc/build && \
	cd glibc/build && \
	../configure --prefix=/usr --disable-werror --enable-static-pie

build: glibc/build/Makefile
	cd glibc/build && \
	make -j && \
	$(foreach i, $(GLIBC_BUILD_TEST_LIST), cd glibc/build ; make test t=$(i) ; true $(NL) )

#	rm -rf build && \

PWD=$(shell pwd)

$(APPDIR):
	$(APPBUILDER) -i mystikos/glibc-test:0.1
	cp $(CURDIR)/tests.passed $(APPDIR)

$(APPDIR)/bin/run: run.c
	mkdir -p $(APPDIR)/bin
	$(MUSL_GCC) -Wall -o $(APPDIR)/bin/run run.c

$(ROOTFS): 
	$(MYST) mkext2  --force --trace $(APPDIR) $(ROOTFS)

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
#	rm -rf $(APPDIR) $(ROOTFS)

