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

TESTS = $(shell cat supported.txt)

tests: libos
	$(foreach i, $(TESTS), $(MAKE) run TEST=$(i) $(NL) )

TARGET = sgx
EXEC = exec-$(TARGET)

run:
	@ echo "=== TEST=$(TEST)"
	@ rm -rf appdir
	@ mkdir -p appdir/src/functional
	@ install -D $(SRCDIR)/$(TEST) appdir/$(TEST)
	@ cp $(SRCDIR)/src/functional/*.so appdir/src/functional
	$(BINDIR)/libos mkcpio appdir rootfs
	$(BINDIR)/libos $(EXEC) $(OPTS) rootfs $(TEST)

clean:
	rm -rf rootfs appdir $(SRCDIR) ramfs

libos:
	$(MAKE) -C $(TOP)/tools/libos

mutex:
	$(MAKE) run TEST=/src/functional/pthread_mutex.exe
