ifndef TOP
$(error "please define TOP variable")
endif

##==============================================================================
##
## directory locations
##
##==============================================================================

SUBDIR=$(subst $(TOP)/,,$(CURDIR))

BUILDDIR=$(TOP)/build

LIBDIR=$(BUILDDIR)/lib
ifndef SUBLIBDIR
SUBLIBDIR=$(LIBDIR)/$(SUBDIR)
endif

BINDIR=$(BUILDDIR)/bin
ifndef SUBBINDIR
SUBBINDIR=$(BINDIR)/$(SUBDIR)
endif

OBJDIR=$(BUILDDIR)/obj
ifndef SUBOBJDIR
SUBOBJDIR=$(OBJDIR)/$(SUBDIR)
endif

INCDIR=$(TOP)/include

export TESTNAME=$(SUBDIR)$(TESTSUFFIX)
export TESTDIR=$(BUILDDIR)/tests

define NL


endef

##==============================================================================
##
## OE edger8r definitions
##
##==============================================================================

EDGER8R=$(BUILDDIR)/openenclave/bin/oeedger8r

##==============================================================================
##
## Default flags
##
##==============================================================================

DEFAULT_INCLUDES = -I$(INCDIR)

DEFAULT_CFLAGS = -Wall -Werror -g -fPIC

DEFAULT_LDFLAGS =

##==============================================================================
##
## OE common definitions
##
##==============================================================================

OE_INCDIR = $(BUILDDIR)/openenclave/include
OE_BINDIR += $(BUILDDIR)/openenclave/bin

##==============================================================================
##
## OE enclave definitions
##
##==============================================================================

OEENCLAVE_INCLUDES =
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty/libc
OEENCLAVE_INCLUDES += -I$(INCDIR)
OEENCLAVE_INCLUDES += -I$(TOP)/include

OEENCLAVE_LIBDIR = $(BUILDDIR)/openenclave/lib/openenclave/enclave

OEENCLAVE_LDFLAGS = -nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,-gc-sections -L$(OEENCLAVE_LIBDIR) -loeenclave -loecryptombed -lmbedtls -lmbedx509 -lmbedcrypto -loelibc -loesyscall -loecore

OEENCLAVE_CFLAGS_LAX = -g -nostdinc -m64 -fPIE -ftls-model=local-exec -fstack-protector-strong -fno-omit-frame-pointer -ffunction-sections -fdata-sections

OEENCLAVE_CFLAGS_STRICT = -Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers -Wno-type-limits

OEENCLAVE_CFLAGS = $(OEENCLAVE_CFLAGS_LAX) $(OEENCLAVE_CFLAGS_STRICT)

##==============================================================================
##
## OE host definitions
##
##==============================================================================

OEHOST_INCLUDES = -I$(OE_INCDIR)

OEHOST_LIBDIR = $(BUILDDIR)/openenclave/lib/openenclave/host

OEHOST_LDFLAGS = -L$(OEHOST_LIBDIR) -Wl,-z,noexecstack -loehost -ldl -lpthread -lsgx_enclave_common -lsgx_dcap_ql -lssl -lcrypto

OEHOST_CFLAGS = -g -Wall -Werror

##==============================================================================
##
## MUSL definitions
##
##==============================================================================

MUSL_GCC=$(BUILDDIR)/host-musl/bin/musl-gcc
MUSL_LIB=$(BUILDDIR)/host-musl/lib

##==============================================================================
##
## gdb definitions
##
##==============================================================================

LIBOS_GDB=$(BUILDDIR)/bin/libos-gdb
OEGDB=$(BUILDDIR)/openenclave/bin/oegdb

##==============================================================================
##
## edger8r options
##
##==============================================================================

EDGER8R_TRUSTED_OPTS =
EDGER8R_TRUSTED_OPTS += --trusted
EDGER8R_TRUSTED_OPTS += --search-path $(OE_INCDIR)
EDGER8R_TRUSTED_OPTS += --trusted-dir $(SUBOBJDIR)

EDGER8R_UNTRUSTED_OPTS =
EDGER8R_UNTRUSTED_OPTS += --untrusted
EDGER8R_UNTRUSTED_OPTS += --search-path $(OE_INCDIR)
EDGER8R_UNTRUSTED_OPTS += --untrusted-dir $(SUBOBJDIR)

include $(TOP)/config.mak

##==============================================================================
##
## Define $(EXEC) macro in terms of $(TARGET). This macro should be used in
## tests as follows:
##
##     $ libos $(EXEC) rootfs <program-name> <args...>
##
## The target may be set when running the tests as shown in the following two
## examples.
##
##     $ make TARGET=sgx tests
##     $ make TARGET=linux tests
##
##==============================================================================

TARGET = sgx
EXEC = exec-$(TARGET)

##==============================================================================
##
## GDB
##     Use "make GDB=1" to run debugger
##
##==============================================================================

GDB_COMMAND = $(BINDIR)/libos-gdb --args

ifdef GDB
__GDB_COMMAND = $(GDB_COMMAND)
endif

##==============================================================================
##
## MEMCHECK
##     Use "make MEMCHECK=1" to check for memory leaks.
##
##==============================================================================

MEMCHECK_COMMAND = valgrind
MEMCHECK_COMMAND += --tool=memcheck
MEMCHECK_COMMAND += --leak-check=full

ifdef MEMCHECK
__MEMCHECK_COMMAND = $(MEMCHECK_COMMAND)
export TARGET=linux
endif

##==============================================================================
##
## VGDB
##     Use "make VGDB=1" to run the Valgrind gdb server
##
##==============================================================================

VGDB_COMMAND = $(MEMCHECK_COMMAND)
VGDB_COMMAND += --vgdb=yes
VGDB_COMMAND += --vgdb-error=0

ifdef VGDB
__VGDB_COMMAND = $(VGDB_COMMAND)
export TARGET=linux
endif

##==============================================================================
##
## CACHEGRIND
##     Use "make CACHEGRIND=1" to profile performance
##
##==============================================================================

CACHEGRIND_COMMAND = valgrind
CACHEGRIND_COMMAND += --tool=cachegrind
CACHEGRIND_COMMAND += --cachegrind-out-file=cachegrind.out

ifdef CACHEGRIND
__CACHEGRIND_COMMAND = $(CACHEGRIND_COMMAND)
export TARGET=linux
endif

##==============================================================================
##
## CALLGRIND
##     Use "make CALLGRIND=1" to profile performance
##
##==============================================================================

CALLGRIND_COMMAND = valgrind
CALLGRIND_COMMAND += --tool=callgrind
CALLGRIND_COMMAND += --callgrind-out-file=callgrind.out
CALLGRIND_COMMAND += --vgdb=yes
CALLGRIND_COMMAND += --vgdb-error=0

ifdef CALLGRIND
__CALLGRIND_COMMAND = $(CALLGRIND_COMMAND)
export TARGET=linux
endif

##==============================================================================
##
## PREFIX
##
##==============================================================================

ifdef __GDB_COMMAND
PREFIX += $(__GDB_COMMAND)
endif

ifdef __MEMCHECK_COMMAND
PREFIX += $(__MEMCHECK_COMMAND)
endif

ifdef __VGDB_COMMAND
PREFIX += $(__VGDB_COMMAND)
endif

ifdef __CACHEGRIND_COMMAND
PREFIX += $(__CACHEGRIND_COMMAND)
endif

ifdef __CALLGRIND_COMMAND
PREFIX += $(__CALLGRIND_COMMAND)
endif

##==============================================================================
##
## LIBOS command
##
##==============================================================================

LIBOS_EXEC += $(PREFIX)
LIBOS_EXEC += $(BINDIR)/libos
LIBOS_EXEC += $(EXEC)

LIBOS = $(BINDIR)/libos

##==============================================================================
##
## RUNTEST command
##
##==============================================================================

RUNTEST_COMMAND=$(TOP)/scripts/runtest
