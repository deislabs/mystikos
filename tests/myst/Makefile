TOP=$(abspath ../..)
include $(TOP)/defs.mak

DIRS =
DIRS += mkcpio
DIRS += exec-not-signed

ifneq ($(TARGET),linux)
DIRS += exec-signed-1
DIRS += exec-signed-2
endif

DIRS += exec-package
DIRS += dump-package

DIRS += cwd-config

include $(TOP)/rules.mak
