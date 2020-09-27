TOP=$(abspath ..)
include $(TOP)/defs.mak

TARGET = $(LIBDIR)/liboscrt.so

CFLAGS = -m64 -g -fPIC -Werror

INCLUDES = -I$(INCDIR)

SOURCES = $(wildcard *.c)

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
DEFINES = -DLIBOS_ENABLE_GCOV
endif

LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -nostdlib -nodefaultlibs -nostartfiles

LDFLAGS1 += -Wl,-elibos_enter_crt

LDFLAGS2 = -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now

ifdef LIBOS_ENABLE_GCOV
LDFLAGS2 += -L$(LIBDIR)
LDFLAGS2 += -lgcov_musl
endif

LDFLAGS2 += -Wl,--whole-archive

LIBS = $(LIBDIR)/libosglibccompat.a

LIBCC = -lgcc

-include $(TOP)/third_party/enclave-musl/musl/objects.mak

OBJECTS = $(addprefix $(SUBOBJDIR)/,$(SOURCES:.c=.o))

$(TARGET): $(MUSL_OBJECTS) $(OBJECTS) $(LIBS)
	mkdir -p $(LIBDIR)
	$(CC) -o $@ $(LDFLAGS1) $(OBJECTS) $(MUSL_OBJECTS) $(LIBCC) $(LDFLAGS2) $(LIBS)

$(SUBOBJDIR)/%.o: %.c
	mkdir -p $(SUBOBJDIR)
	$(shell mkdir -p $(shell dirname $@))
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

tests:
