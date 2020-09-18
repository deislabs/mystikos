TOP = $(abspath ../..)
include $(TOP)/defs.mak

IMG=libos-alpine
APPDIR=$(CURDIR)/appdir

ifdef STRACE
OPTS = --strace
endif

SRCDIR = $(SUBOBJDIR)/srcdir

all: $(SRCDIR) build

$(SRCDIR):
	rm -rf $(SRCDIR)
	mkdir -p $(SUBOBJDIR)
	cp -r $(TOP)/third_party/libc-test $(SRCDIR)

build:
	sudo docker run --rm -v $(SRCDIR):/srcdir $(IMG) bash -c "make -C srcdir"

ifdef ALLTESTS
TEST_FILE = alltests.txt
else
  ifdef FAILED
    TEST_FILE = failed.txt
  else
    TEST_FILE = tests.txt
  endif
endif

TESTS = $(shell cat $(TEST_FILE))

tests: libos
	@ $(foreach i, $(TESTS), TESTNAME=$(TESTNAME)$(i)$(TESTSUFFIX) $(RUNTEST) $(MAKE) run TEST=$(i) $(NL) )

run:
	@ echo "=== TEST=$(TEST)"
	@ rm -rf appdir
	@ mkdir -p appdir/src/functional
	@ install -D $(SRCDIR)/$(TEST) appdir/$(TEST)
	@ cp $(SRCDIR)/src/functional/*.so appdir/src/functional
	$(BINDIR)/libos mkcpio appdir rootfs
	$(LIBOS_EXEC) $(OPTS) rootfs $(TEST)

clean:
	rm -rf rootfs appdir $(SRCDIR) ramfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

mutex:
	$(MAKE) run TEST=/src/functional/pthread_mutex.exe
