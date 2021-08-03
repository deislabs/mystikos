# Redis Solution

This solution spins up a redis server in an enclave and sends some requests to it from a native client

## Makefile targets

To make and run this solution using a cpio/ramfs, use: 
```
make run 
```

To make and run this solution using a ext2fs, use: 
```
make ext2
```

To make and run this solution using native alpine, use: 
```
make native 
```

### Performance testing on redis

We added a tool here that uses the standard redis-benchmark to calculate the performance of the redis transactions we see. 

In order to collect transaction times for a varying number of clients/transactions, run - 
```
make perf
```

To get the benchmark numbers for one iteration which would contain native, sgx and linux, and display them in a comparison format, run -
```
./perf.sh
```
