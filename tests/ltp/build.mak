PKGS = bash build-base automake autoconf linux-headers glib bison flex gawk xz

FILTER += confstr
FILTER += fmtmsg
FILTER += getcontext
FILTER += rt_tgsigqueueinfo
FILTER += timer_create

all:
	apk add $(PKGS)
	make autotools
	./configure
	$(MAKE) clean > /dev/null 2> /dev/null
	$(MAKE) __build -f build.mak

__build:
	$(MAKE) -C ./lib FILTER_OUT_DIRS="$(FILTER)"
	$(MAKE) -C ./testcases/kernel/syscalls FILTER_OUT_DIRS="$(FILTER)"
