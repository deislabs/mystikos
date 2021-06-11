### Debugging managed dotnet code

## Prerequisites
1. lldb:
```
sudo apt install lldb-10
```
2. dotnet-sos:
```
dotnet tool install -g dotnet-sos
# Installs the SOS extension, and
# updates .lldbinit file to load SOS on lldb startup
dotnet-sos install
```
3. oelldb, SGX enclave extension for lldb:
```
git clone --branch working https://github.com/vtikoo/oelldb
ln -s <path-to-oelldb-dir>/oelldb /usr/bin/oelldb
```

## Example

```
make
make run-ext2-lldb
```


Dotnet runtime issues a lot of cpuid instructions, which generate a SIGILL inside the enclave. To handle these run after the mystikos process is launched -
```
pro hand -p true -s false -n false SIGILL
```

Or alternatively import the ignore_sigill python script -
```
script import ignore_sigill
```

Some SOS commands -
```
soshelp
bpmd hello.dll hello.Program.Main
clrstack
clrthreads
clrmodules
```

To enable SOS debug logging -
```
logging enable
dbgout
```
