.NOTPARALLEL:
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

#original ltp source
#URL=https://github.com/linux-test-project/ltp
#BRANCH=master

URL=https://github.com/vtikoo/ltp
BRANCH=paulcallen/revert-fork

OPTS += --app-config-path config.json

# *** end fork related settings ***

ifeq ($(FS),hostfs)
OPTS+= --host-to-enc-uid-map 0:0,1:1,2:2,65534:65534,100700:700,100702:702,100703:703,1001000:1000
OPTS+= --host-to-enc-gid-map 0:0,1:1,2:2,65534:65534,100701:701,100704:704,100705:705,1001000:1000
endif

TESTS=$(shell grep -v "^\#" $(FS)_tests_passed.txt)

# remove gcov exception tests when running code coverage
ifdef MYST_ENABLE_GCOV
TESTS=$(shell comm -23 $(FS)_tests_passed.txt $(FS)_tests_gcov_exceptions.txt)
endif

# overlayfs directories
LOWERDIR=$(CURDIR)/appdir
UPPERDIR=$(CURDIR)/upper
WORKDIR=$(CURDIR)/work
HOSTFS=$(CURDIR)/hostfs

# Bash functions
GROUPADD = while sudo lsof /etc/group; do sleep 3; done; \
			sudo groupadd
USERADD = while sudo lsof /etc/passwd; do sleep 3; done; \
			sudo useradd

all: ext2fs

ext2fs: appdir
	$(MYST) mkext2 --force appdir ext2fs

appdir:
	$(MAKE) clone
	$(MAKE) build

build:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak"
	sudo chown -R $(USER).$(USER) appdir
	$(MAKE) password-file
	$(MAKE) group-file
	$(MAKE) add_host_users_and_groups

all-ubuntu: native-build
	$(MYST) mkext2 --force native_appdir native_ext2fs

native-build: native-clone
	cp build.mak native_appdir/Makefile
	$(MAKE) -C native_appdir native-all

native-build-one: native-clone
	cp -p build.mak native_appdir/Makefile
	$(MAKE) -C native_appdir native-one TEST=$(TEST)

native-run-one:
	./native_appdir$(TEST)

rebuild:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak build"
	sudo chown -R $(USER).$(USER) appdir
	$(MAKE) password-file
	$(MAKE) group-file

clone:
	sudo rm -rf appdir
	mkdir -p appdir
	git clone $(URL) appdir/ltp -b $(BRANCH)

native-clone:
	sudo rm -rf native_appdir
	mkdir -p native_appdir
	git clone $(URL) native_appdir/ltp -b $(BRANCH)

password-file:
	mkdir -p appdir/etc
	# fmt for /etc/passwd:
	# login name:pwd:uid:gid:comment:home dir: login shell
	echo "root:x:0:0:root:/root:/bin/bash" > appdir/etc/passwd
	echo "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" >> appdir/etc/passwd
	echo "bin:x:2:2:bin:/bin:/usr/sbin/nologin" >> appdir/etc/passwd
	echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" >> appdir/etc/passwd
	echo "user700:x:700:701::/:/bin/bash" >> appdir/etc/passwd
	echo "user702:x:702:701::/:/bin/bash" >> appdir/etc/passwd
	echo "user703:x:703:701::/:/bin/bash" >> appdir/etc/passwd
	echo "user1000:x:1000:1000::/:/bin/bash" >> appdir/etc/passwd

group-file:
	mkdir -p appdir/
	# fmt for /etc/group:
	# group name:pwd:gid:user list
	echo "root:x:0:" > appdir/etc/group
	echo "daemon:x:1:" >> appdir/etc/group
	echo "bin:x:2:" >> appdir/etc/group
	echo "nogroup:x:65534:" >> appdir/etc/group
	echo "grp701:x:701:user700" >> appdir/etc/group
	echo "grp704:x:704:" >> appdir/etc/group
	echo "grp705:x:705:" >> appdir/etc/group
	echo "grp1000:x:1000:" >> appdir/etc/group

add_host_users_and_groups:
	$(GROUPADD) -f -g 100701 grp701
	$(GROUPADD) -f -g 100704 grp704
	$(GROUPADD) -f -g 100705 grp705
	$(GROUPADD) -f -g 101000 grp1000
	id -u user700 >/dev/null 2>&1 || $(USERADD) -g grp701 -u 100700 user700
	id -u user702 >/dev/null 2>&1 || $(USERADD) -g grp701 -u 100702 user702
	id -u user703 >/dev/null 2>&1 || $(USERADD) -g grp701 -u 100703 user703
	id -u user1000 >/dev/null 2>&1 || $(USERADD) -g grp1000 -u 101000 user1000

del_host_users_and_groups:
	sudo userdel user700 || true
	sudo userdel user702 || true
	sudo userdel user703 || true
	sudo userdel user1000 || true
	sudo groupdel grp701 || true
	sudo groupdel grp704 || true
	sudo groupdel grp705 || true
	sudo groupdel grp1000 || true

tests: tests_hostfs tests_ext2fs tests_ramfs

tests_hostfs:
ifdef MYST_ENABLE_HOSTFS
	$(MAKE) alltests FS=hostfs
endif

tests_ext2fs:
	$(MAKE) alltests FS=ext2fs

tests_ramfs:
	$(MAKE) alltests FS=ramfs

alltests:
	$(foreach i, $(TESTS), $(MAKE) one FS=$(FS) TEST=$(i) $(NL) )

clean:
	sudo rm -rf $(APPDIR) ext2fs appdir $(UPPERDIR) $(WORKDIR) $(HOSTFS)
	$(MAKE) del_host_users_and_groups

native-clean:
	sudo rm -rf native_appdir ext2fs

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
	sudo chown -R 0.0 $(HOSTFS)
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

##==============================================================================
##
## pipe-tests:
##
##==============================================================================

PIPE_TESTS =
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe01
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe03
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe04
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe06
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe08
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe09
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe/pipe10
PIPE_TESTS += /ltp/testcases/kernel/syscalls/pipe2/pipe2_01
PIPE_TESTS += /ltp/testcases/kernel/syscalls/epoll_wait/epoll_wait01

pipe-tests:
	$(foreach i, $(PIPE_TESTS), $(MAKE) one FS=ext2fs TEST=$i $(NL) )
