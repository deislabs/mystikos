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

ifeq ($(FS),hostfs)
OPTS+= --host-to-enc-uid-map 0:0,1:1,2:2,65534:65534,100700:700,100702:702,100703:703,1001000:1000
OPTS+= --host-to-enc-gid-map 0:0,1:1,2:2,65534:65534,100701:701,100704:704,100705:705,1001000:1000
endif

# run all the tests for the nightly pipeline
ifdef MYST_NIGHTLY_TEST
TESTS=$(shell grep -v "^\#" $(FS)_tests_passed.txt)
else
# run only filesystem based tests for the PR pipeline
TESTS=$(shell grep -v "^\#" $(FS)_fs_tests_passed.txt)
endif

# remove gcov exception tests when running code coverage
ifdef MYST_ENABLE_GCOV
TESTS=$(shell comm -23 $(FS)_tests_passed.txt $(FS)_tests_gcov_exceptions.txt)
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
	$(MAKE) password-file
	$(MAKE) group-file
	$(MAKE) add_host_users_and_groups

rebuild:
	cp build.mak appdir/ltp
	docker run --rm -v $(APPDIR):/appdir myst-alpine bash -c "make -j -C appdir/ltp -f build.mak build"
	sudo chown -R $(USER).$(USER) appdir
	$(MAKE) password-file
	$(MAKE) group-file

clone:
	rm -rf appdir
	mkdir appdir
	git clone https://github.com/mikbras/ltp appdir/ltp -b myst

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
	( ! grep /etc/group grp701 ) || sudo groupadd -g 100701 grp701
	( ! grep /etc/group grp704 ) || sudo groupadd -g 100704 grp704
	( ! grep /etc/group grp705 ) || sudo groupadd -g 100705 grp705
	( ! grep /etc/group grp1000 ) || sudo groupadd -g 101000 grp1000
	( ! grep /etc/passwd user700 ) || sudo useradd -g grp701 -u 100700 user700
	( ! grep /etc/passwd user702 ) || sudo useradd -g grp701 -u 100702 user702
	( ! grep /etc/passwd user703 ) || sudo useradd -g grp701 -u 100703 user703
	( ! grep /etc/passwd user1000 ) || sudo useradd -g grp1000 -u 101000 user1000

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
	rm -rf ramfs.appdir
	mkdir -p $(shell dirname ramfs.appdir/$(TEST))
	cp appdir/$(TEST) ramfs.appdir/$(TEST)
	cp -r appdir/etc  ramfs.appdir/
	$(MYST) mkcpio ramfs.appdir ramfs
	sudo -E $(RUNTEST) $(MYST_EXEC) $(OPTS) $(FS) $(TEST) $(NL)
endif

t:
	make one FS=ramfs TEST=/ltp/testcases/kernel/syscalls/setsockopt/setsockopt02
