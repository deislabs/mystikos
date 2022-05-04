TOP = $(abspath ../..)
include $(TOP)/defs.mak

APPBUILDER=$(TOP)/scripts/appbuilder
ROOTFS=hello_server.cpio

ifdef STRACE
OPTS = --strace
endif

all: rootfs

rootfs: appdir
	$(MYST) mkcpio appdir $(ROOTFS)

appdir:
	$(APPBUILDER) -m Dockerfile

_run:
	$(MAKE) run1
	$(MAKE) run2
	
run:
	$(RUNTEST) make -C $(CURDIR) _run

run1:
	test -f server.pid && kill -9 `cat server.pid` || true
	@echo "=== starting flask server ==="
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/python3 /app/flask_app.py 2> server.output & echo $$! > server.pid
	timeout 60s tail -f server.output | ./client.sh "Running on http"
	@echo ""
	@echo "=== stopping flask server ==="
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	test -f client.output
	@echo ""

run2:
	test -f server.pid && kill -9 `cat server.pid` || true
	@echo "=== starting uwsgi server ==="
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/uwsgi /app/uwsgi.ini 2> server.output & echo $$! > server.pid
	timeout 60s tail -f server.output | ./client.sh "spawned uWSGI worker"
	@echo ""
	@echo "=== stopping flask server ==="
	test -f server.pid && kill -9 `cat server.pid` && rm server.pid || true
	test -f client.output
	@echo ""

server-flask:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/python3 /app/flask_app.py

server-uwsgi:
	$(MYST_EXEC) $(OPTS) $(ROOTFS) /usr/local/bin/uwsgi /app/uwsgi.ini

clean:
	test -f server.pid && kill -9 `cat server.pid` || true
	rm -rf $(ROOTFS) appdir server.pid
