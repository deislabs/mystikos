TOP=$(abspath ..)
include $(TOP)/defs.mak

TARGET = $(LIBDIR)/libmystcrt.so

CFLAGS = -m64 -g -fPIC -Werror

INCLUDES = -I$(INCDIR)

SOURCES = $(wildcard *.c) $(wildcard glibc/*.c)

ifdef MYST_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
DEFINES = -DMYST_ENABLE_GCOV
endif

LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -nostdlib -nodefaultlibs -nostartfiles

LDFLAGS1 += -Wl,-emyst_enter_crt

LDFLAGS2 = -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now

ifdef MYST_ENABLE_GCOV
LDFLAGS2 += -L$(LIBDIR)
LDFLAGS2 += -lgcov_musl
endif

LIBCC = -lgcc

MUSLSRC=$(BUILDDIR)/crt-musl

-include $(MUSLSRC)/objects.mak

OBJECTS = $(addprefix $(SUBOBJDIR)/,$(SOURCES:.c=.o))

$(TARGET): $(MUSL_OBJECTS) $(OBJECTS)
	mkdir -p $(LIBDIR)
	$(CC) -o $@ $(LDFLAGS1) $(OBJECTS) $(MUSL_OBJECTS) $(LIBCC) $(LDFLAGS2)

$(SUBOBJDIR)/%.o: %.c
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

tests:
