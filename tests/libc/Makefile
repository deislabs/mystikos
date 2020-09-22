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

TEST_FILE = tests.txt

ifdef ALLTESTS
  RUNTEST=$(RUNTEST_COMMAND)
  TEST_FILE = alltests.txt
endif

ifdef FAILED
  RUNTEST=$(RUNTEST_COMMAND)
  TEST_FILE = failed.txt
  export TIMEOUT=10
endif

TESTS = $(shell cat $(TEST_FILE))

GCOVDIR=$(CURDIR)/gcov

tests: libos
	@ $(foreach i, $(TESTS), TESTNAME=$(TESTNAME)$(i)$(TESTSUFFIX) $(RUNTEST) ./run-libc-test ${LIBOS} ${TARGET} ${SRCDIR} $(i) $(NL) )

clean:
	rm -rf rootfs appdir $(SRCDIR) gcov

libos:
	$(MAKE) -C $(TOP)/tools/libos

mutex:
	$(MAKE) run TEST=/src/functional/pthread_mutex.exe
