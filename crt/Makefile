TOP=$(abspath ..)
include $(TOP)/defs.mak

TARGET = $(LIBDIR)/libmystcrt.so

CFLAGS = -m64 -g -fPIC -Werror

ifdef MYST_ENABLE_GCOV2
CFLAGS += -fprofile-arcs -ftest-coverage
endif

INCLUDES = -I$(INCDIR) -I$(TOP)/build/musl/include

DEFINES = $(MYST_DEFINES)

ifdef MYST_ENABLE_GCOV2
DEFINES += -DMYST_ENABLE_GCOV2
endif

SOURCES = $(wildcard *.c) $(wildcard $(TOP)/third_party/gcompat/gcompat/libgcompat/*.c)

MUSLSRC=$(TOP)/third_party/musl/crt/musl

ifdef MYST_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
endif

LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -nostdlib -nodefaultlibs -nostartfiles

LDFLAGS1 += -Wl,-emyst_enter_crt

LDFLAGS2 = -shared -Wl,-Bstatic -Wl,--export-dynamic -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,--dynamic-list=$(MUSLSRC)/dynamic.list

ifdef MYST_ENABLE_GCOV2
LDFLAGS2 += $(LIBDIR)/libmystgcov.a
LDFLAGS2 += $(LIBDIR)/libmystgcovclient.a
endif

LIBCC = -lgcc

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
