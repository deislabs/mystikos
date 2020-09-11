TOP=$(abspath ../..)
include $(TOP)/defs.mak

PROGRAM = liboskernel.so
TARGET = $(LIBDIR)/$(PROGRAM)
SOURCES = $(wildcard *.c)
INCLUDES += $(OEENCLAVE_INCLUDES)

CFLAGS =
CFLAGS += -g
CFLAGS += -nostdinc
CFLAGS += -m64
CFLAGS += -fPIE
CFLAGS += -ftls-model=local-exec
CFLAGS += -fvisibility=hidden
CFLAGS += -fstack-protector-strong
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -ffunction-sections
CFLAGS += -fdata-sections
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wpointer-arith
CFLAGS += -Wconversion
CFLAGS += -Wextra
CFLAGS += -Wno-missing-field-initializers
CFLAGS += -Wno-type-limits

ifdef LIBOS_ENABLE_GCOV
CFLAGS += -fprofile-arcs
CFLAGS += -ftest-coverage
endif

LDFLAGS =
LDFLAGS += -nostdlib
LDFLAGS += -nodefaultlibs
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,--no-undefined
LDFLAGS += -Wl,-Bstatic
LDFLAGS += -Wl,-Bsymbolic
LDFLAGS += -Wl,--export-dynamic
LDFLAGS += -Wl,-pie
LDFLAGS += -Wl,--build-id
LDFLAGS += -Wl,-z,noexecstack
LDFLAGS += -Wl,-z,now
LDFLAGS += -Wl,-gc-sections
LDFLAGS += -Wl,-elibos_enter_kernel
LDFLAGS += -Wl,--whole-archive

ifdef LIBOS_ENABLE_GCOV
LDFLAGS += -L$(LIBDIR)
LDFLAGS += -lgcov_musl
endif

OBJECTS += $(wildcard $(OBJDIR)/kernel/*.o)
OBJECTS += $(wildcard $(OBJDIR)/shared/*.o)
OBJECTS += $(SUBOBJDIR)/enter.o
OBJECTS += $(SUBOBJDIR)/initfini.o

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LDFLAGS) $(LIBS)
	size $(TARGET)

$(SUBOBJDIR)/enter.o: enter.c
	mkdir -p $(SUBOBJDIR)
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $(SUBOBJDIR)/enter.o enter.c

$(SUBOBJDIR)/initfini.o: initfini.c
	mkdir -p $(SUBOBJDIR)
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $(SUBOBJDIR)/initfini.o initfini.c

CLEAN = $(TARGET)
CLEAN += $(SUBOBJDIR)/enter.o
CLEAN += $(SUBOBJDIR)/initfini.o

clean:
	rm -f $(CLEAN)

tests:
