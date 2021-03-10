This is a simple demo of a basic python webserver using common frameworks.

At this time, neither Flask nor uWSGI work, because:
- Flask requires SYS_fork
- uWSGI requires SYS_get_robust_list, even when invoked in single-process mode

Building with `make` will copy both samples into the myst runtime. You can then
select which one to invoke at run time:

Flask
---

```
myst exec-sgx hello_server.cpio /usr/local/bin/python3 /app/flask_app.py
```

uWSGI
---

```
myst exec-sgx hello_server.cpio /usr/local/bin/uwsgi /app/uwsgi.ini
```
