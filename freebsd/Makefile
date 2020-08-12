TOP = $(abspath ..)
SUBDIR = freebsd
include $(TOP)/defs.mak

all:
	docker build --quiet -t libos-freebsd .

save:
	docker save -o img.tar libos-alpine

clean:
