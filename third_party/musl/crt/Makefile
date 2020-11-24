TOP=$(abspath ../../..)
include $(TOP)/defs.mak
include $(TOP)/config.mak

WHICH_GCC = $(shell which gcc)

CFLAGS = -g -Werror -fPIC

ifeq ($(LIBOS_RELEASE),1)
CFLAGS += -Og
endif

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
endif

MUSLSRC=$(BUILDDIR)/crt-musl

all: muslsrc $(MUSLSRC)/config.mak
	( cd $(MUSLSRC); $(MAKE) CC="$(WHICH_GCC) $(CFLAGS)" )

clean:
ifneq ($(wildcard $(MUSLSRC)),)
	( cd $(MUSLSRC) && make clean )
	rm -f $(MUSLSRC)/config.mak
endif

distclean:
ifneq ($(wildcard $(MUSLSRC)),)
	( cd $(MUSLSRC); make distclean )
endif

$(MUSLSRC)/config.mak:
	( cd $(MUSLSRC); ./configure --enable-debug=yes --disable-optimize )

tests:

diff:
	$(MAKE) -C $(MUSLSRC) distclean
	-diff -r ../musl/musl $(MUSLSRC) > musl.diff
	@echo "Created musl.diff"

PATCHDIR=$(TOP)/third_party/musl/crt

muslsrc: $(MUSLSRC)

$(MUSLSRC):
	mkdir -p $(BUILDDIR)
	git clone git://git.musl-libc.org/musl -b v1.2.0 $(MUSLSRC)
	( cd $(MUSLSRC); git apply $(PATCHDIR)/patch1.diff )
	( cd $(MUSLSRC); git apply $(PATCHDIR)/patch2.diff )
