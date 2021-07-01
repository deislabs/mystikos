TOP=$(abspath ..)
include $(TOP)/defs.mak

TARGET = $(LIBDIR)/libmystcrt.so

CFLAGS = -m64 -g -fPIC -Werror

ifdef MYST_ENABLE_GCOV
CFLAGS += -fprofile-arcs -ftest-coverage
endif

CFLAGS += $(OPTIMIZATION_CFLAGS)

MUSLSRC=$(TOP)/third_party/musl/crt/musl

INCLUDES = -I$(INCDIR) 
INCLUDES += -I$(TOP)/build/musl/include
INCLUDES += -I$(MUSLSRC)/src/internal
INCLUDES += -I$(MUSLSRC)/arch/x86_64/

DEFINES = $(MYST_DEFINES)

ifdef MYST_ENABLE_GCOV
DEFINES += -DMYST_ENABLE_GCOV
endif

SOURCES =
SOURCES += $(wildcard *.c)
SOURCES += $(wildcard $(TOP)/third_party/gcompat/gcompat/libgcompat/*.c)
SOURCES += ../asm/setjmp.s
SOURCES += ../asm/longjmp.s
SOURCES += ../asm/callonstack.s


LDFLAGS1 = -Wl,--sort-section,alignment -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=both -Wl,--no-undefined -Wl,--exclude-libs=ALL -nostdlib -nodefaultlibs -nostartfiles

LDFLAGS1 += -Wl,-emyst_enter_crt

LDFLAGS2 = -shared -Wl,-Bstatic -Wl,--export-dynamic -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,--dynamic-list=$(MUSLSRC)/dynamic.list

ifdef MYST_ENABLE_GCOV
LDFLAGS2 += $(LIBDIR)/libmystgcov.a
LDFLAGS2 += $(LIBDIR)/libmystgcovclient.a
endif

LIBCC = -lgcc

-include $(MUSLSRC)/objects.mak

__OBJECTS1 = $(SOURCES:.c=.o)
__OBJECTS2 = $(__OBJECTS1:.s=.o)
OBJECTS = $(addprefix $(SUBOBJDIR)/,$(__OBJECTS2))

$(TARGET): $(MUSL_OBJECTS) $(OBJECTS)
	mkdir -p $(LIBDIR)
	$(CC) -o $@ $(LDFLAGS1) $(OBJECTS) $(MUSL_OBJECTS) $(LIBCC) $(LDFLAGS2)

$(SUBOBJDIR)/%.o: %.c
	mkdir -p $(SUBOBJDIR)
	mkdir -p $(shell dirname $@)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

$(SUBOBJDIR)/%.o: %.s
	mkdir -p $(SUBOBJDIR)
	mkdir -p $(shell dirname $@)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

tests:
