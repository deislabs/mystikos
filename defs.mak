ifndef SUBDIR
$(error "please define SUBDIR variable")
endif

LIBDIR=$(TOP)/build/lib
ifndef SUBLIBDIR
SUBLIBDIR=$(LIBDIR)/$(SUBDIR)
endif

BINDIR=$(TOP)/build/bin
ifndef SUBBINDIR
SUBBINDIR=$(BINDIR)/$(SUBDIR)
endif

OBJDIR=$(TOP)/build/obj
ifndef SUBOBJDIR
SUBOBJDIR=$(OBJDIR)/$(SUBDIR)
endif

INCDIR=$(TOP)/build/include

EDGER8R=$(BINDIR)/oeedger8r

OEENCLAVE_LDFLAGS = -nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,-gc-sections -L$(LIBDIR)/openenclave/enclave -loeenclave -loecryptombed -lmbedtls -lmbedx509 -lmbedcrypto -loelibc -loesyscall -loecore

OEENCLAVE_CFLAGS_LAX = -g -nostdinc -m64 -fPIE -ftls-model=local-exec -fvisibility=hidden -fstack-protector-strong -fno-omit-frame-pointer -ffunction-sections -fdata-sections

OEENCLAVE_CFLAGS_STRICT = -Wall -Werror -Wextra -Wno-missing-field-initializers -Wno-type-limits

#OEENCLAVE_CFLAGS_STRICT = -Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers -Wno-type-limits

OEENCLAVE_CFLAGS = $(OEENCLAVE_CFLAGS_LAX) $(OEENCLAVE_CFLAGS_STRICT)
#OEENCLAVE_CFLAGS = $(OEENCLAVE_CFLAGS_LAX)

OEHOST_LDFLAGS = -L$(LIBDIR)/openenclave/host -Wl,-z,noexecstack -loehost -ldl -lpthread -lsgx_enclave_common -lsgx_dcap_ql -lssl -lcrypto

OEHOST_CFLAGS = -g -Wall -Werror

define NL

endef

MUSL_GCC=$(TOP)/build/host-musl/bin/musl-gcc
MUSL_LIB=$(TOP)/build/host-musl/lib
