# Guide to investigating failures in build logs

This is a basic guide to get started on investigating build failures. Logs are large and these are some tips to get started.

When there is a failure, there will be a sequence of the following messages:

* recipe for target '????' failed.
* ] Error 1
* ] Error 2
* Waiting for unfinished jobs

As an example, look at this log below:

```
[2022-02-06T23:12:51.753Z] Head "https://mcr.microsoft.com/v2/dotnet/sdk/manifests/6.0": dial tcp 204.79.197.219:443: i/o timeout

[2022-02-06T23:12:51.753Z] Makefile:15: recipe for target 'appdir' failed

[2022-02-06T23:12:51.753Z] make[4]: *** [appdir] Error 1

[2022-02-06T23:12:51.753Z] make[4]: Leaving directory '/home/oeadmin/workspace/Mystikos/Standalone-Pipelines/Solutions-Tests-Pipeline/tests/dotnet-ubuntu'
[2022-02-06T23:12:51.753Z] fetch http://dl-cdn.alpinelinux.org/alpine/v3.10/main/x86_64/APKINDEX.tar.gz

[2022-02-06T23:12:51.753Z] Makefile:148: recipe for target 'dotnet-ubuntu' failed

[2022-02-06T23:12:51.753Z] make[3]: *** [dotnet-ubuntu] Error 2

[2022-02-06T23:12:51.753Z] make[3]: *** Waiting for unfinished jobs....
```


## In order to find the failure in the log-
* Search for the first "recipe for target".
* Then "Error 1" means the bottom of the nesting of makefiles.
* Then "Error 2" means the next level up in make file nesting.
* And finally after the "real" failure, you will see it print "waiting for unfinished jobs"(which means it failed but now it has to wait for other parallel jobs to finish before exiting).
