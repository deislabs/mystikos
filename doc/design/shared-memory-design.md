### MAP_SHARED semantics and POSIX shared memory.
The two MAP_SHARED scenarios supported are:
- regular file or anonymous MAP_SHARED.
- POSIX shared memory: mapping a file descriptor obtained by `shm_open`. 

#### Design Overview:
Kernel maintains a list of shared mappings. Mappings are refcounted based on number of processes sharing the memory region.

Sharing can occur either via:

- Inheritance of MAP_SHARED mappings in the child process.
- For posix shared memory only: mapping the same shared memory file.

On execve, the inherited shared mappings in the child are unmapped.

#### POSIX shared memory specific changes:
- Created another instance of memory based ramfs file system - shmfs. Mounted on /dev/shm.
- File system provides files whose contents start at a page-aligned boundary. `myst_buf_t` implementation was extended to support page-aligned buffers.
- mmap of shmfs files returns the addr of the contents of the file. Processes can achieve shared memory by mmap'ing the same shmfs file.
- Release of shmfs regular file is delayed until all three conditions are met: no opens, no links, and no process mapping the file.

#### Regular file and anonymous MAP_SHARED changes:
- Delayed deallocation of memory region.
- Writeback for file mappings: Memory region is written back to backing file on last munmap.

#### Limitations of MAP_SHARED and posix shared memory support:

1. Unsupported scenarios for memory related syscalls (mmap, munmap, mremap, mprotect, msync) -
- mmap with both addr hint and MAP_FIXED flag specified. If MAP_FIXED is not specified, addr hint is disregarded.
- Partial munmaps, mprotect, mremap of shared memory object. Partial here means if the address range specified by the memory syscall is a subset of the range returned by the `mmap()` or last `mremap()` associated with the address range. 
- mprotect when there are >1 processes sharing the memory region. We avoid supporting this because we multiplex a single host process inside the enclave. And page protections on the host are per-process.
- mremap is disabled for posix shared memory. For regular file or anonymous MAP_SHARED mremap is unsupported  if >1 processes are sharing the memory region.

2. /proc/[pid]/maps currently does not list shared mappings. This can be addressed and is not a design limitation.

3. Resizing a posix shared memory file with writes or by truncation is unsupported if the file is serving any mmap request. We avoid supporting this because resizing a ramfs file can potentially move the underlying buffer.

4. User may map region larger than file and later grow the file either by ftruncate or write. Although according to the open group mmap man page this is unspecified behavior(see quote below), on Linux the new file region will be available in the mapping. Because Mystikos copies the region of file into memory at mmap() time, later modifications in the file are not reflected in the mapping.
 
 > If the size of the mapped file changes after the call to mmap() as a result of some other operation on the mapped file, the effect of references to portions of the mapped region that correspond to added or removed portions of the file is unspecified.

From [mmap (opengroup.org) ](https://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html)

#### fdmappings related changes:
- For a file mapping we used to store a process specific file descriptor. Changed this to a ref-counted, process-agnostic file handle object. Ref-counted tracking makes partial mapping and unmapping work. Process-agnostic is required if region is shared by multiple processes memory.
- Deprecated fdmapping->pathname. Pathname is now fetched via file's fs_realpath method. 
- Handle fdmapping updation on mremap.

#### Memory ownership check changes:
- Shared mappings are not tracked in the pids vector. So memory ownership check now additionally looks in the shared memory list.
- Added ownership check to munmap, mprotect and msync syscalls.
