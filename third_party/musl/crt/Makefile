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

PATCHDIR=$(TOP)/third_party/musl/crt

muslsrc: $(MUSLSRC)

$(MUSLSRC):
	mkdir -p $(BUILDDIR)
	git clone git://git.musl-libc.org/musl -b v1.2.0 $(MUSLSRC)
	( cd $(MUSLSRC); git apply $(PATCHDIR)/patch1.diff )
	( cd $(MUSLSRC); git apply $(PATCHDIR)/patch2.diff )

##==============================================================================
##
## genpatch -- regenerates patch1.diff and patch2.diff
##
##==============================================================================

NEWFILES += src/internal/__popcountdi2.c
NEWFILES += src/stdio/__fprintf_chk.c
NEWFILES += src/stdio/__vfprintf_chk.c

genpatch: all
	( cd $(MUSLSRC); make clean )
	( cd $(MUSLSRC); make distclean )
	( cd $(MUSLSRC); $(foreach i, $(NEWFILES), git add $(i) ; ) )
	( cd $(MUSLSRC); git diff --cached --staged > $(PATCHDIR)/patch1.diff )
	( cd $(MUSLSRC); git diff > $(PATCHDIR)/patch2.diff )
