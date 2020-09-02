ifndef SUBDIR
$(error "please define SUBDIR variable")
endif

##==============================================================================
##
## directory locations
##
##==============================================================================

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
