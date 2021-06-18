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

## Viewing dotnet code

SOS by itself has no mechanims for viewing HL dotnet code.
You can import - 
```
script import code_view
```
This adds two features to lldb - 
- A breakpoint hook which prints the dotnet source whenever a breakpoint is hit.
- `print_dotnet_source` command which can be run on the lldb command line to print the dotnet source.

A possible debugging workflow is to setup a breakpoint where you want to break, and step through instructions, using the `print_dotnet_source` to keep track of where you are in the dotnet code.

### Setup:

- SOS needs to have access to the pdb files for access to source/line information.
This can be provided by - 
```
setsymbolserver -directory <path-to-dir-containing-pdb>
```

- `DOTNET_SOURCE_DIRS` environment variable. This is a colon separated path of source directories where `code_view` script will look for dotnet source files.

See `make run-ext2-lldb` as a reference example for this setup.