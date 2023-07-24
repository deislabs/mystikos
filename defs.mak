ifndef TOP
$(error "please define TOP variable")
endif

include $(TOP)/config.mak

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

ifndef BINDIR
BINDIR=$(BUILDDIR)/bin
endif
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

ifeq ($(MYST_RELEASE),1)
OPTIMIZATION_CFLAGS += -O3 -fno-omit-frame-pointer
endif

ifdef MYST_ENABLE_GCOV
GCOV_CFLAGS += -O0 -fprofile-arcs -ftest-coverage
endif

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
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty/openssl_3
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty/libc
OEENCLAVE_INCLUDES += -I$(OE_INCDIR)/openenclave/3rdparty/mbedtls
OEENCLAVE_INCLUDES += -I$(INCDIR)
OEENCLAVE_INCLUDES += -I$(TOP)/include

OEENCLAVE_LIBDIR = $(BUILDDIR)/openenclave/lib/openenclave/enclave

OEENCLAVE_LDFLAGS = $(shell PKG_CONFIG_PATH=$(BUILDDIR)/openenclave/share/pkgconfig pkg-config oeenclave-gcc --libs)

OEENCLAVE_LDFLAGS += $(shell PKG_CONFIG_PATH=$(BUILDDIR)/openenclave/share/pkgconfig pkg-config oeenclave-gcc --variable=${MYST_OE_CRYPTO}libs)

OEENCLAVE_CFLAGS = $(shell PKG_CONFIG_PATH=$(BUILDDIR)/openenclave/share/pkgconfig pkg-config oeenclave-gcc --cflags) -g

##==============================================================================
##
## OE host definitions
##
##==============================================================================

OEHOST_INCLUDES = -I$(OE_INCDIR)

OEHOST_LIBDIR = $(BUILDDIR)/openenclave/lib/openenclave/host

OEHOST_LDFLAGS = -L$(OEHOST_LIBDIR) -Wl,-z,noexecstack -loehost -ldl -lpthread -lssl -lcrypto

OEHOST_CFLAGS = -g -Wall -Werror

##==============================================================================
##
## MUSL definitions
##
##==============================================================================

MUSL_GCC=$(BUILDDIR)/musl/bin/musl-gcc
MUSL_LIB=$(BUILDDIR)/musl/lib

##==============================================================================
##
## MBEDTLS definitions
##
##==============================================================================

MBEDTLS_PREFIX=$(BUILDDIR)/mbedtls
MBEDTLS_INCDIR=$(MBEDTLS_PREFIX)/include
MBEDTLS_LIBDIR=$(MBEDTLS_PREFIX)/lib

MBEDTLS_LIBS =
MBEDTLS_LIBS += $(MBEDTLS_LIBDIR)/libmbedcrypto.a
MBEDTLS_LIBS += $(MBEDTLS_LIBDIR)/libmbedtls.a
MBEDTLS_LIBS += $(MBEDTLS_LIBDIR)/libmbedx509.a

##==============================================================================
##
## gdb definitions
##
##==============================================================================

MYST_GDB=$(BUILDDIR)/bin/myst-gdb
OEGDB=$(BUILDDIR)/openenclave/bin/oegdb

##==============================================================================
##
## lldb definitions
##
##==============================================================================

MYST_LLDB=$(BUILDDIR)/bin/myst-lldb
OELLDB=$(BUILDDIR)/openenclave/bin/oelldb

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

##==============================================================================
##
## MYST_DEFINES
##
##==============================================================================

MYST_DEFINES =

ifdef MYST_ENABLE_GCOV
MYST_DEFINES += -DMYST_ENABLE_GCOV
endif

ifdef MYST_ENABLE_LEAK_CHECKER
MYST_DEFINES += -DMYST_ENABLE_LEAK_CHECKER
endif

ifdef MYST_ENABLE_HOSTFS
MYST_DEFINES += -DMYST_ENABLE_HOSTFS
endif

ifdef MYST_ENABLE_EXT2FS
MYST_DEFINES += -DMYST_ENABLE_EXT2FS
endif

ifdef MYST_DEBUG
MYST_DEFINES += -DMYST_DEBUG
endif

##==============================================================================
##
## Define $(EXEC) macro in terms of $(TARGET). This macro should be used in
## tests as follows:
##
##     $ myst $(EXEC) rootfs <program-name> <args...>
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

ifdef GDB_BIN
GDB_COMMAND = $(GDB_BIN) --args
else
GDB_COMMAND = $(BINDIR)/myst-gdb --args
endif

ifdef GDB
__GDB_COMMAND = $(GDB_COMMAND)
endif

##==============================================================================
##
## LLDB
##     Use "make LLDB=1" to run debugger
##
##==============================================================================

ifdef LLDDB_BIN
LLDDB_COMMAND = $(LLDDB_BIN) --
else
LLDDB_COMMAND = $(BINDIR)/myst-lldb --
endif

ifdef LLDB
__LLDB_COMMAND = $(LLDB_COMMAND)
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

ifdef __LLDB_COMMAND
PREFIX += $(__LLDB_COMMAND)
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
## MYST command
##
##==============================================================================

ifdef MYST_BIN
MYST = $(MYST_BIN)
else
MYST = $(BINDIR)/myst
endif

MYST_EXEC += $(PREFIX)
MYST_EXEC += $(MYST)
MYST_EXEC += $(EXEC)

##==============================================================================
##
## RUNTEST command
##
##==============================================================================

RUNTEST_COMMAND=$(TOP)/scripts/runtest

##==============================================================================
##
## MKROOTFS script
##
##==============================================================================

MKROOTFS=$(TOP)/scripts/mkrootfs

##==============================================================================
##
## MYST_RETRY script
##			Retries action 5 times with a doubling backoff, starting at 1s.
##==============================================================================

MYST_RETRY=$(TOP)/scripts/myst-retry
