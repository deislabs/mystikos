TOP=$(abspath ../../..)
include $(TOP)/defs.mak
include $(TOP)/config.mak

WHICH_GCC = $(shell which gcc)

CFLAGS = -g -Werror -fPIC

ifeq ($(MYST_RELEASE),1)
CFLAGS += -Og
endif

ifdef MYST_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
endif

MUSLSRC=$(BUILDDIR)/crt-musl

THISDIR=$(CURDIR)

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

genpatch:
	rm -f patch.diff
	( cd $(MUSLSRC); git diff > $(THISDIR)/patch.diff )
	( cd $(MUSLSRC); git diff --cached >> $(THISDIR)/patch.diff )

PATCHDIR=$(TOP)/third_party/musl/crt

muslsrc: $(MUSLSRC)

NEWFILES =
NEWFILES += src/internal/__popcountdi2.c
NEWFILES += src/stdio/__fprintf_chk.c
NEWFILES += src/stdio/__vfprintf_chk.c

$(MUSLSRC):
	mkdir -p $(BUILDDIR)
	git clone git://git.musl-libc.org/musl -b v1.2.0 $(MUSLSRC)
	( cd $(MUSLSRC); git apply $(PATCHDIR)/patch.diff )
	$(foreach i, $(NEWFILES), ( cd $(MUSLSRC); git add $(i) ); $(NL) )
