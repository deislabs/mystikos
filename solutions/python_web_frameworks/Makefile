TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder

ifdef STRACE
OPTS = --strace
endif

all: app 

app:
	$(APPBUILDER) -f cpio -o hello_server.cpio Dockerfile 

#run:
#	test -f server.pid && kill -9 `cat server.pid` || true
#	$(MYST_EXEC) $(OPTS) hello_server.cpio /usr/local/bin/python3 /app/flask_app.py & echo $$! > server.pid
#	sleep 10
#	curl 127.0.0.1:8000
#	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
run:
	@ echo "Please see the README for instructions on how to exercise these tests"

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf hello_server.cpio server.pid
