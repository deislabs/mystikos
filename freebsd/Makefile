TOP = $(abspath ..)
SUBDIR = freebsd
include $(TOP)/defs.mak

all:
	sudo docker build --quiet -t libos-freebsd .

save:
	sudo docker save -o img.tar libos-alpine

clean:
