TOP=$(abspath ../..)
include $(TOP)/defs.mak

DOCKER_BUILD_EXT2=$(TOP)/scripts/docker-build-ext2

all: rootfs

rootfs: build/Dockerfile
	$(DOCKER_BUILD_EXT2) rootfs -q build

OPTS =
OPTS += --thread-stack-size=1m
OPTS += --memory-size=1g

tests: rootfs
	$(MYST_EXEC) $(OPTS) rootfs /app/hello

clean:
	rm -rf appdir rootfs
