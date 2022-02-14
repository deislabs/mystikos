PKGS = bash build-base automake autoconf linux-headers glib bison flex gawk xz
UBUNTU_PKGS = PKGS = gcc git make pkgconf autoconf automake bison flex m4 linux-headers-$(uname -r) libc6-dev

FILTER += confstr
FILTER += fmtmsg
FILTER += getcontext
FILTER += rt_tgsigqueueinfo
FILTER += timer_create

ifdef TEST
TESTDIR=$(shell dirname $(TEST))
TESTNAME=$(shell basename $(TEST))
endif

all:
	apk add $(PKGS)
	make autotools
	./configure
	$(MAKE) clean > /dev/null 2> /dev/null
	$(MAKE) build -f build.mak

build:
	$(MAKE) -C ./lib FILTER_OUT_DIRS="$(FILTER)"
	$(MAKE) -C ./testcases/kernel/syscalls FILTER_OUT_DIRS="$(FILTER)"
	$(MAKE) -C ./testcases/open_posix_testsuite FILTER_OUT_DIRS="$(FILTER)"

native-all:
	$(MAKE) native-config
	$(MAKE) native-lib
	$(MAKE) native-build

native-config:
	$(MAKE) -C ltp autotools
	( cd ltp; ./configure )
	touch native-config

native-lib:
	$(MAKE) -C ./ltp/lib FILTER_OUT_DIRS="$(FILTER)"
	touch native-lib

native-build:
	$(MAKE) -C ./ltp/testcases/kernel/syscalls FILTER_OUT_DIRS="$(FILTER)"

ifdef TEST
native-one:
	$(MAKE) native-config
	$(MAKE) native-lib
	rm -f ./$(TEST)
	$(MAKE) -C ./$(TESTDIR) MAKE_TARGETS=$(TESTNAME)
endif

clean:
	$(MAKE) clean
	rm -f native-lib native-config
