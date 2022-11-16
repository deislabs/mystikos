# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import gdb
import math
import tempfile

def round_up_page_size(x):
    return ((x + 4095) // 4096) * 4096

class myst_list_t:
    OFFSETOF_HEAD=0
    SIZEOF_HEAD=8

    OFFSETOF_TAIL=8
    SIZEOF_TAIL=8

    OFFSETOF_SIZE=16
    SIZEOF_SIZE=8

    def __init__(self, addr):
        self.head = read_int_from_memory(addr + self.OFFSETOF_HEAD, self.SIZEOF_HEAD)
        self.tail = read_int_from_memory(addr + self.OFFSETOF_TAIL, self.SIZEOF_TAIL)
        self.size = read_int_from_memory(addr + self.OFFSETOF_SIZE, self.SIZEOF_SIZE)

class myst_vad_t:
    OFFSETOF_NEXT = 0
    SIZEOF_NEXT = 8

    OFFSETOF_PREV = 8
    SIZEOF_PREV = 8

    OFFSETOF_ADDR = 16
    SIZEOF_ADDR = 8

    OFFSETOF_SIZE = 24
    SIZEOF_SIZE = 8

    OFFSETOF_PROT = 32
    SIZEOF_PROT = 2

    OFFSETOF_FLAGS = 34
    SIZEOF_FLAGS = 2

    def __init__(self, addr):
        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)
        self.prev = read_int_from_memory(addr + self.OFFSETOF_PREV, self.SIZEOF_PREV)
        self.addr = read_int_from_memory(addr + self.OFFSETOF_ADDR, self.SIZEOF_ADDR)
        self.size = read_int_from_memory(addr + self.OFFSETOF_SIZE, self.SIZEOF_SIZE)
        self.flags = read_int_from_memory(addr + self.OFFSETOF_FLAGS, self.SIZEOF_FLAGS)

class mman_file_handle_t:
    OFFSETOF_FS = 16
    SIZEOF_FS = 8

    OFFSETOF_INODE = 32
    SIZEOF_INODE = 8

    def __init__(self, addr):
        if not addr:
            self.fs = None
            self.inode = None
            return
        self.fs = read_int_from_memory(addr + self.OFFSETOF_FS, self.SIZEOF_FS)
        self.inode = read_int_from_memory(addr + self.OFFSETOF_INODE, self.SIZEOF_INODE)

    @staticmethod
    def equal(f1, f2):
        if not f1 and not f2:
            return True
        elif not f1 or not f2:
            return False
        elif f1.fs == f2.fs and f1.inode == f2.inode:
            return True
        return False

FDMAPPING_SIZE = 32
FDMAPPING_USED_MAGIC = 0x1ca0597f
class myst_fdmapping_t:
    OFFSETOF_USED = 0
    SIZEOF_USED = 4

    OFFSETOF_OFFSET = 8
    SIZEOF_OFFSET = 8

    OFFSETOF_FILESZ = 16
    SIZEOF_FILESZ = 8

    OFFSETOF_MMAN_FILE_HANDLE = 24
    SIZEOF_MMAN_FILE_HANDLE = 8

    def __init__(self, addr):
        if addr:
            self.used = read_int_from_memory(addr + self.OFFSETOF_USED, self.SIZEOF_USED)
        else:
            return

        self.offset = read_int_from_memory(addr + self.OFFSETOF_OFFSET, self.SIZEOF_OFFSET)
        self.filesz = read_int_from_memory(addr + self.OFFSETOF_FILESZ, self.SIZEOF_FILESZ)
        self.mman_file_handle = read_int_from_memory(addr + self.OFFSETOF_MMAN_FILE_HANDLE, self.SIZEOF_MMAN_FILE_HANDLE)

class proc_w_count_t:
    SIZEOF_PREV=8

    OFFSETOF_NEXT=8
    SIZEOF_NEXT=8

    OFFSETOF_PID=16
    SIZEOF_PID=4

    OFFSETOF_NMAPS=20
    SIZEOF_NMAPS=24

    def __init__(self, addr):
        if addr:
            self.prev = read_int_from_memory(addr, self.SIZEOF_PREV)
        else:
            return

        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)
        self.pid = read_int_from_memory(addr + self.OFFSETOF_PID, self.SIZEOF_PID)
        self.nmaps = read_int_from_memory(addr + self.OFFSETOF_NMAPS, self.SIZEOF_NMAPS)

SHMEM_TYPE_ANON = 1
SHMEM_TYPE_REG_FILE = 2
SHMEM_TYPE_POSIX_SHM = 3
class shared_mapping_t:
    OFFSETOF_PREV=0
    SIZEOF_PREV=8

    OFFSETOF_NEXT=8
    SIZEOF_NEXT=8

    OFFSETOF_SHARERS_HEAD=16
    SIZEOF_SHARERS_HEAD=8

    OFFSETOF_SHARERS_TAIL=24
    SIZEOF_SHARERS_TAIL=8

    OFFSETOF_SHARERS_SIZE=32
    SIZEOF_SHARERS_SIZE=8

    OFFSETOF_START_ADDR=40
    SIZEOF_START_ADDR=8

    OFFSETOF_LENGTH=48
    SIZEOF_LENGTH=8

    OFFSETOF_FILE_SIZE=56
    SIZEOF_FILE_SIZE=8

    OFFSETOF_FILE_HANDLE=64
    SIZEOF_FILE_HANDLE=8

    OFFSETOF_OFFSET=72
    SIZEOF_OFFSET=8

    OFFSETOF_TYPE=80
    SIZEOF_TYPE=4

    def __init__(self, addr):
        if addr:
            self.prev = read_int_from_memory(addr + self.OFFSETOF_PREV, self.SIZEOF_PREV)
        else:
            return

        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)
        self.sharers_head = read_int_from_memory(addr + self.OFFSETOF_SHARERS_HEAD, self.SIZEOF_SHARERS_HEAD)
        self.sharers_tail = read_int_from_memory(addr + self.OFFSETOF_SHARERS_TAIL, self.SIZEOF_SHARERS_TAIL)
        self.sharers_size = read_int_from_memory(addr + self.OFFSETOF_SHARERS_SIZE, self.SIZEOF_SHARERS_SIZE)
        self.start_addr = read_int_from_memory(addr + self.OFFSETOF_START_ADDR, self.SIZEOF_START_ADDR)
        self.length = read_int_from_memory(addr + self.OFFSETOF_LENGTH, self.SIZEOF_LENGTH)
        self.file_size = read_int_from_memory(addr + self.OFFSETOF_FILE_SIZE, self.SIZEOF_FILE_SIZE)
        self.file_handle = read_int_from_memory(addr + self.OFFSETOF_FILE_HANDLE, self.SIZEOF_FILE_HANDLE)
        self.offset = read_int_from_memory(addr + self.OFFSETOF_OFFSET, self.SIZEOF_OFFSET)
        self.type = read_int_from_memory(addr + self.OFFSETOF_TYPE, self.SIZEOF_TYPE)

class MystShmfsInitBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(MystShmfsInitBreakpoint, self).__init__('myst_shmfs_setup_hook', internal=False)

    def stop(self):
        mman_tracker.shared_mappings = int(gdb.parse_and_eval("$rdi"))
        #print("mman shared_mappings = %x" % (mman_tracker.shared_mappings))

OFFSETOF_KARGS_MMAN_PIDS_DATA = 0
OFFSETOF_KARGS_MMAN_PIDS_SIZE = 8
OFFSETOF_KARGS_FDMAPPINGS_DATA = 16
OFFSETOF_KARGS_FDMAPPINGS_SIZE = 24

OFFSETOF_MMAN_BASE = 16
OFFSETOF_MMAN_SIZE = 24
OFFSETOF_MMAN_PROT_VECTOR = 32
OFFSETOF_MMAN_START = 40
OFFSETOF_MMAN_END = 48
OFFSETOF_MMAN_BRK = 56
OFFSETOF_MMAN_VAD_LIST = 96

PTR_SIZE = 8
SIZET_SIZE = 8

class MystMmanInitBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(MystMmanInitBreakpoint, self).__init__('myst_mman_init_debug_hook', internal=False)

    def stop(self):
        mman_ptr = int(gdb.parse_and_eval("$rdi"))
        kargs_ptr = int(gdb.parse_and_eval("$rsi"))
        
        mman_tracker.mman_base = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_BASE, PTR_SIZE)
        mman_tracker.mman_start = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_START, PTR_SIZE)
        mman_tracker.mman_brk = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_BRK, PTR_SIZE)
        mman_tracker.mman_end = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_END, PTR_SIZE)
        mman_tracker.mman_size = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_SIZE, SIZET_SIZE)
        mman_tracker.prot_vector = read_int_from_memory(mman_ptr + OFFSETOF_MMAN_PROT_VECTOR, PTR_SIZE)
        mman_tracker.vad_list_ptr = mman_ptr + OFFSETOF_MMAN_VAD_LIST

        mman_tracker.process_ownership_vec = read_int_from_memory(kargs_ptr + OFFSETOF_KARGS_MMAN_PIDS_DATA, PTR_SIZE)
        mman_tracker.process_ownership_vec_size = read_int_from_memory(kargs_ptr + OFFSETOF_KARGS_MMAN_PIDS_SIZE, SIZET_SIZE)
        mman_tracker.file_mappings_vec = read_int_from_memory(kargs_ptr + OFFSETOF_KARGS_FDMAPPINGS_DATA, PTR_SIZE)
        mman_tracker.file_mappings_vec_size = read_int_from_memory(kargs_ptr + OFFSETOF_KARGS_FDMAPPINGS_SIZE, SIZET_SIZE)

        # print("mman base= %x start=%x end=%x size=%d vad_list_ptr=%x" % (mman_tracker.mman_base, mman_tracker.mman_start, mman_tracker.mman_end, mman_tracker.mman_size, mman_tracker.vad_list_ptr))
        # print("file_map_vec= 0x%x ownership_vec= 0x%x prot_vector=0x%x" % (mman_tracker.file_mappings_vec, mman_tracker.process_ownership_vec, mman_tracker.prot_vector))

        # Continue execution.
        return False

class MystMmanTracker:

    def __init__(self):
        self._welcome()

    # Dispatch the command
    def dispatch(self, arg0, *args):
        if arg0 == "-h":
            self._help()
        # elif arg0 == "-p":
        #     self._dump_maps_by_pids(*args)
        else:
            self._get_map_by_addr(arg0, *args)
    
    def shutdown(self):
        pass # do shutdown things

    def _welcome(self):
        self._print('\nmyst-gdb has been configured to track mman data structures.' +
                    '\nType myst-mman for more information\n')

    def _print(self, msg):
        print('\033[0;32m%s\033[0m' % msg)

    def _help(self):
        msg = 'myst-mman: Mystikos heap memory tracker\n' \
            'Commands:\n' \
            '  \033[0;32mmyst-mman <address-expression> \033[0m\n' \
            '    Print details for memory region associated with address.\n' \
            '    Examples:\n' \
            '      gdb) myst-prot $rip \n' \
            '  \033[0;32mmyst-mman [-h]\033[0m\n' \
            '    Print help\n'
            # TODO: print mappings by process
            # '  \033[0;32mmyst-mman [-p] <pid>\033[0m\n' \

        print(msg)

    def _is_valid_heap_addr_range(self, addr, length):
        if length >= 0 and addr >= mman_tracker.mman_base and addr <= mman_tracker.mman_end:
            addr_end = addr + length
            if addr_end <= mman_tracker.mman_end:
                return True
        return False

    def _lookup_vad_list(self, addr):
        if not addr:
            return
        vad_list = read_int_from_memory(mman_tracker.vad_list_ptr, 8)
        if not vad_list:
            print("No allocations yet.")
            return
        vad = myst_vad_t(vad_list)
        if addr >= vad.addr and addr < vad.addr + vad.size:
            return vad            
        while vad.next:
            vad = myst_vad_t(vad.next)
            if addr >= vad.addr and addr < vad.addr + vad.size:
                return vad

    def _print_vad(self, vad):
        print("VAD start addr=0x%x VAD end addr=0x%x size=%d prot=%s" % (vad.addr, vad.addr + vad.size, vad.size, vad.prot))
 
    '''
    Mman region layout:
    <guard-page><-VADs/Vector-><PROT-VECTOR><--BREAK--><--UNASSIGNED--><---MAPPED----><guard-page>
    [............................................................................................]
                ^                           ^          ^               ^             ^
            mman_base                   mman_start  mman_brk        mman_map      mman_end
    pids and fd mapping vectors track pages starting mman_base.
    prot vector tracks pages starting mman_start.
    '''

    def _get_pids_or_fd_index(self, addr):
        return (addr - mman_tracker.mman_base) // 4096
    
    def _get_prot_vec_index(self, addr):
        return (addr - mman_tracker.mman_start) // 4096
    
    def _pids_index_to_addr(self, index):
        return mman_tracker.mman_base + index * 4096

    def _prot_index_to_addr(self, index):
        return mman_tracker.mman_start + index * 4096

    def _get_pids_by_index(self, index):
        return read_int_from_memory(mman_tracker.process_ownership_vec + (index * 4), 4)

    def _get_fdmapping_by_index(self, index):
        return myst_fdmapping_t(mman_tracker.file_mappings_vec + (index * FDMAPPING_SIZE))
    
    def _get_prot_by_index(self, index):
        return read_int_from_memory(mman_tracker.prot_vector + index, 1)

    def _get_prot_by_addr(self, addr):
        return self._get_prot_by_index(self._get_prot_vec_index(addr))

    def _prot_to_string(self, prot):
        if  prot == 0:
            return "PROT_NONE";
        elif prot == 1:
            return "PROT_READ";
        elif prot == 2:
            return "PROT_WRITE";
        elif prot == 3:
            return "PROT_READ|PROT_WRITE";
        elif prot == 4:
            return "PROT_EXEC";
        elif prot == 5:
            return "PROT_READ|PROT_EXEC";
        elif prot == 7:
            return "PROT_READ|PROT_WRITE|PROT_EXEC";
        else:
            return "unknown";

    def _handle_private_mapping(self, addr):
        index = self._get_pids_or_fd_index(addr)
        addr_pids_entry = self._get_pids_by_index(index)
        addr_fd_entry = self._get_fdmapping_by_index(index)
        addr_prot_entry = self._get_prot_by_index(self._get_prot_vec_index(addr))

        '''
        scan left on fd, prot and pids vec
        '''
        lowest_idx = self._get_pids_or_fd_index(mman_tracker.mman_start)
        tmp_index = index
        while tmp_index >= lowest_idx:
              if self._get_pids_by_index(tmp_index) == addr_pids_entry:
                fd_entry = self._get_fdmapping_by_index(index)
                if not addr_fd_entry.used == fd_entry.used:
                    break
                if not mman_file_handle_t.equal( \
                            mman_file_handle_t(addr_fd_entry.mman_file_handle), \
                            mman_file_handle_t(fd_entry.mman_file_handle)):
                    break
                if not addr_prot_entry == self._get_prot_by_addr( \
                                            self._pids_index_to_addr(tmp_index)):
                    break
                tmp_index -= 1
        # while loop stops when either file, prot, pids property has changed.
        # So the start index is the page right of tmp_index.
        map_start_pids_idx = tmp_index + 1
        map_start_addr = self._pids_index_to_addr(map_start_pids_idx)

        '''
        scan right on fd, prot and pids vec
        '''
        highest_idx_plus_one = self._get_pids_or_fd_index(mman_tracker.mman_end)
        tmp_index = index
        while tmp_index < highest_idx_plus_one:
              if self._get_pids_by_index(tmp_index) == addr_pids_entry:
                fd_entry = self._get_fdmapping_by_index(index)
                if not addr_fd_entry.used == fd_entry.used:
                    break
                if not mman_file_handle_t.equal(mman_file_handle_t(addr_fd_entry.mman_file_handle), mman_file_handle_t(fd_entry.mman_file_handle)):
                    break
                if not addr_prot_entry == self._get_prot_by_addr(self._pids_index_to_addr(tmp_index)):
                    break
                tmp_index += 1
        # while loop stops when either file, prot, pids property has changed.
        # So tmp_index is pointing to the page beyond the end of the mapping.
        # End address of mapping is not inclusive, so we can directly use tmp_index here.
        map_end_pids_idx = tmp_index
        map_end_addr = self._pids_index_to_addr(map_end_pids_idx)
        map_size = map_end_addr - map_start_addr

        print("start_addr=0x%x end_addr=0x%x size=%d(0x%x)" % (map_start_addr, map_end_addr, map_size, map_size))
        print("Page protection = %s" % (self._prot_to_string(addr_prot_entry)))
        print("MAP_PRIVATE mapping, owning process: %d" % (addr_pids_entry))
        if addr_fd_entry.used == FDMAPPING_USED_MAGIC:
            print("File mapping info: offset=%d filesz=%d" % (addr_fd_entry.offset - (index - map_start_pids_idx)*4096, addr_fd_entry.filesz))

    def _shmem_type_to_string(self, type):
        if type == SHMEM_TYPE_ANON:
            return "Anonymous"
        elif type == SHMEM_TYPE_REG_FILE:
            return "Regular file"
        elif type == SHMEM_TYPE_POSIX_SHM:
            return "POSIX Shared Memory file"
        else:
            return "Unknown"

    def _print_sharers_list(self, sharers):
        proc = proc_w_count_t(sharers)
        print("Owning processes: ")
        while True:
            print("%d" % (proc.pid))
            if proc.next:
                proc = proc_w_count_t(proc.next)
            else:
                break

    def _lookup_shared_mappings(self, addr):
        assert(mman_tracker.shared_mappings)
        shmem_list = myst_list_t(mman_tracker.shared_mappings)
        if not shmem_list.head:
            print("No shared mappings yet.")
            return -1

        sm = shared_mapping_t(shmem_list.head)
        while True:
            if addr >= sm.start_addr:
                if sm.type == SHMEM_TYPE_POSIX_SHM:
                    size = sm.file_size
                else:
                    size = sm.length
                size = round_up_page_size(size)
                map_end_addr = sm.start_addr + size
                if addr <= map_end_addr:
                    addr_prot_entry = self._get_prot_by_index(self._get_prot_vec_index(addr))
                    print("start_addr: 0x%x end_addr: 0x%x size=%d(0x%x)" % (sm.start_addr, map_end_addr, size, size))
                    print("Page protection = %s" % (self._prot_to_string(addr_prot_entry)))
                    print("MAP_SHARED mapping, type: %s" % (self._shmem_type_to_string(sm.type)))
                    if sm.type >= SHMEM_TYPE_REG_FILE:
                        addr_fd_entry = self._get_fdmapping_by_index(self._get_pids_or_fd_index(addr))
                        print("File mapping info: offset=%d filesz=%d" % (sm.offset, addr_fd_entry.filesz))
                    self._print_sharers_list(sm.sharers_head)
                    return 0
            if not shmem_list.next:
                break
            else:
                sm = shared_mapping_t(shmem_list.next)
        return -1

    def _get_map_by_addr(self, addr_str):
        # Evaluate the address expression.
        addr = int(gdb.parse_and_eval(addr_str))
        print('address: %s = 0x%x' % (addr_str, addr))

        if not self._is_valid_heap_addr_range(addr, 0):
            print('invalid address!! Not in mman controlled region.')
            return

        index = self._get_pids_or_fd_index(addr)
        addr_pids_entry = self._get_pids_by_index(index)

        if not addr_pids_entry:
            '''
            addr lies either in shared memory, kernel owned or unallocated region.
            For shared memory, parse shared memory list.
            For kernel owned, there should be a corresponding VAD node.
            '''
            ret = self._lookup_shared_mappings(addr)
            if ret == -1: # shared memory not found
                vad = self._lookup_vad_list(addr)
                if vad:
                    print("Kernel owned memory region")
                    print("VAD info for addr=0x%x:" % (addr))
                    self._print_vad(vad)
                else:
                    print("Unallocated memory region")
            return

        # if we are here, this is a MAP_PRIVATE mapping
        self._handle_private_mapping(addr)

        # vad = self._lookup_vad_list(addr)
        # if vad:
        #     print("VAD info for addr=0x%x:" % (addr))
        #     self._print_vad(vad)

    def _dump_maps_by_pids(self):
        pass

mman_tracker = None


command = """
define myst-mman
  if $argc == 4
      python mman_tracker.dispatch("$arg0", $arg1, $arg2, $arg3)
  end
  if $argc == 3
      python mman_tracker.dispatch("$arg0", $arg1, $arg2)
  end
  if $argc == 2
      python mman_tracker.dispatch("$arg0", $arg1)
  end
  if $argc == 1
      python mman_tracker.dispatch("$arg0")
  end
  if $argc == 0
      python mman_tracker.dispatch("-h")
  end
end
"""

if __name__ == "__main__":
    mman_tracker = MystMmanTracker()
    # Register breakpoints
    MystMmanInitBreakpoint()
    MystShmfsInitBreakpoint()

    # Register command with gdb.
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(command)
        f.flush()
        gdb.execute('source %s' % f.name)
    def exit_handler(event):
       global mman_tracker
       mman_tracker.shutdown()
    gdb.events.exited.connect(exit_handler)
