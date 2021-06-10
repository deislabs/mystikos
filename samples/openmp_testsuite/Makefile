TOP=$(abspath ../..)
include $(TOP)/defs.mak

CONTAINER_NAME=omp.myst.apline.062021
CONTAINER_IMAGE_FLAVOR=alpine
CONTAINER_IMAGE_VERSION=3.8
GCC_VERSION=7.5.0

ID=$(shell docker run -d $(CONTAINER_NAME))

all: appdir rootfs

EXT2FS_SIZE=2147483648

rootfs:
	sudo $(MYST) mkext2 --force --size $(EXT2FS_SIZE) appdir rootfs
	sudo truncate --size=-4096 rootfs

appdir:
	docker build -t $(CONTAINER_NAME) . \
	--build-arg IMAGE_FLAVOR=$(CONTAINER_IMAGE_FLAVOR) \
	--build-arg IMAGE_VERSION=$(CONTAINER_IMAGE_VERSION) \
	--build-arg GCC_VERSION=$(GCC_VERSION)
	$(MAKE) export

export:
	docker stop $(ID)
	docker export $(ID) -o image.tar
	rm -rf appdir
	mkdir -p appdir
	tar xf image.tar -C appdir

TESTS=$(shell cat passed.tests)

define NL


endef

OPTS = --memory-size=32m

tests:
	$(foreach i, $(TESTS), $(MYST_EXEC) rootfs $(i) $(OPTS) $(NL) )

clean:
	rm -rf appdir image.tar rootfs
