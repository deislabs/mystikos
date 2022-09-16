Documenting two concurrency related issues which arose in the memory manager and the proposed solution. 

#### 1. Race condition:

Mystikos memory manager is a multi-tiered subsystem - syscall, mman wrapper(mmanutils.c), core mman(mman.c). Different layers update different data structures. The atomicity for these updations should span the layers.

Two threads can interleave in a way which can lead to inconsistent view of memory allocated and the process owning it.

Resources/data structures updated at the core mman layer:
- Active Virtual Address Descriptors(VAD) doubly linked list.
- Free VADs singly linked list.
- Unused VADs: i.e section of VAD array between mman->next_vad and mman->end_vad.
- Vector storing page protection information.

Resources/data structures updated at the mman wrapper layer:
- Vector storing file mapping information.
- Shared memory list.

Resources/data structures updated at the syscall layer:
- Vector storing process ownership information.

<ins>Proposed solution:</ins>
Move the syscall handler for affected memory syscalls under the critical section, with the recursive mman lock. Even the memory ownership test based on pids vector happens atomically with the rest of syscall. Another thread can munmap the mapping between the ownership check passing and the critical section proper of the routine.

Merge shared memory lock with the recursive mman lock. 

#### 2. Potential deadlock between mman lock and filesystem lock lockfs:

Both mman and in-kernel filesystems - i.e ramfs and ext2fs, have code paths which can cause a thread holding one lock to try acquire the other lock, leading to a deadlock.
Note - hostfs does not have this issue, as it doesn't use lockfs.

Have Lockfs want mman lock:
ext2fs and ramfs file systems are wrapped with a lockfs wrapper, which provides a file-system wide lock. Which means that at any given time atmost one thread will be in the file system routines.
Implementations of both ext2fs and ramfs can malloc/free memory, which could in turn cause a mmap() or munmap().

Have mman lock want lockfs:

Flows in the memory manager which can cause file operations:

1. mmap of file mappings.
2. mremap: shrinking  of a file mapping.
3. munmap of a MAP_SHARED file mapping.
4. process shutdown: releasing unreleased MAP_SHARED file mappings.
5. /proc/[pid]/maps callback: this uses fs_realpath to get pathname.

<ins>Proposed solution:</ins>
Generalize the lockfs lock even more.
Currently it is at the granularity of a filesystem instance. Proposal is to make a single global lock for all ramfs and ext2fs instances.
Then, above flows can acquire the global filesystem lock before acquiring the recursive mman lock. This part is an application of a deadlock avoidance mechanism - Banker's algorithm.

Checking for the subcases in 2.-5. requires parsing either file mapping vector for the range or shared memory list. We avoid this and unconditionally acquire the filesystem lock in these cases.
For 1.) filesystem lock is acquired only if a non-negative file descriptor has been passed(proxy for file mapping).
For 2.) we can easily check for shrinking, but not for file mapping.

During implementation, another circular wait situation emerged between the lockfs lock and the fdtable lock. This happened during processing a SYS_mmap file mapping request. This is the only flow in the memory manager where a thread holding the lockfs lock requests for the fdtable lock. Banker's algorithm was applied here too, i.e in `_SYS_mmap` both lockfs and fdtable locks are acquired if its a file mapping.
