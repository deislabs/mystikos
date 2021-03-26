### Debugging managed dotnet code

## Prerequisites
1. lldb:
```
sudo apt install lldb-8
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
git clone https://github.com/anakrish/oelldb
ln -s <path-to-oelldb-dir>/oelldb /usr/bin/oelldb
```

## Example

```
make
make run-ext2-lldb
```
