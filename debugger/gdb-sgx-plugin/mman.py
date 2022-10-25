# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import gdb
import math
import tempfile

class myst_list_t:
    OFFSETOF_HEAD=0
    SIZEOF_HEAD=8

    OFFSETOF_TAIL=8
    SIZEOF_TAIL=8

    OFFSETOF_SIZE=16
    SIZEOF_SIZE=8

    def __init__(self):
        self.head = read_int_from_memory(addr + self.OFFSETOF_HEAD, self.SIZEOF_HEAD)
        self.tail = read_int_from_memory(addr + self.OFFSETOF_TAIL, self.SIZEOF_TAIL)
        self.size = read_int_from_memory(addr + self.OFFSETOF_SIZE, self.SIZEOF_SIZE)

class myst_list_node_t:
    OFFSETOF_HEAD=0
    SIZEOF_HEAD=8

    OFFSETOF_TAIL=8
    SIZEOF_TAIL=8

    OFFSETOF_SIZE=16
    SIZEOF_SIZE=8

    def __init__(self):
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

    OFFSETOF_PROT = 30
    SIZEOF_PROT = 2

    OFFSETOF_FLAGS = 32
    SIZEOF_FLAGS = 2

    def __init__(self, addr):
        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)
        self.prev = read_int_from_memory(addr + self.OFFSETOF_PREV, self.SIZEOF_PREV)
        self.addr = read_int_from_memory(addr + self.OFFSETOF_ADDR, self.SIZEOF_ADDR)
        self.size = read_int_from_memory(addr + self.OFFSETOF_SIZE, self.SIZEOF_SIZE)
        self.flags = read_int_from_memory(addr + self.OFFSETOF_FLAGS, self.SIZEOF_FLAGS)

class mman_file_handle_t:
    SIZEOF_FS = 8

    OFFSETOF_INODE = 8
    SIZEOF_INODE = 8

    def __init__(self, addr):
        if not addr:
            self.fs = None
            self.inode = None
            return
        self.fs = read_int_from_memory(addr, self.SIZEOF_FS)
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

# Definition must align with myst_fdmapping_t structure defined in include/myst/mmanutils.h
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

class shared_mapping_t:
    OFFSETOF_BASE=0
    SIZEOF_BASE=16

    OFFSETOF_SHARERS=16
    SIZEOF_SHARERS=24

    OFFSETOF_START_ADDR=48
    SIZEOF_START_ADDR=8

    OFFSETOF_LENGTH=56
    SIZEOF_LENGTH=8

    OFFSETOF_FILE_SIZE=64
    SIZEOF_FILE_SIZE=8

    OFFSETOF_FILE_HANDLE=72
    SIZEOF_FILE_HANDLE=8

    OFFSETOF_OFFSET=80
    SIZEOF_OFFSET=8

    OFFSETOF_TYPE=88
    SIZEOF_TYPE=4

    def __init__(self, addr):
        if addr:
            self.base = read_int_from_memory(addr + self.OFFSETOF_BASE, self.SIZEOF_BASE)
        else:
            return

        self.sharers = read_int_from_memory(addr + self.OFFSETOF_SHARERS, self.SIZEOF_SHARERS)
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
        mman_tracker.shared_mappings = int(gdb.parse_and_eval('(uint64_t)shmem_list'))    

class MystMmanInitBreakpoint(gdb.Breakpoint):
    def __init__(self):
        super(MystMmanInitBreakpoint, self).__init__('myst_mman_init_debug_hook', internal=False)

    def stop(self):
        mman_tracker.mman_base = int(gdb.parse_and_eval('(uint64_t)_mman->base'))
        mman_tracker.mman_start = int(gdb.parse_and_eval('(uint64_t)_mman->start'))
        mman_tracker.mman_brk = int(gdb.parse_and_eval('(uint64_t)_mman->brk'))
        mman_tracker.mman_map = int(gdb.parse_and_eval('(uint64_t)_mman->map'))
        mman_tracker.mman_end = int(gdb.parse_and_eval('(uint64_t)_mman->end'))
        mman_tracker.mman_size = int(gdb.parse_and_eval('(uint64_t)_mman->size'))
        mman_tracker.file_mappings_vec = int(gdb.parse_and_eval('(uint64_t)__myst_kernel_args.fdmappings_data'))
        mman_tracker.file_mappings_vec_size = int(gdb.parse_and_eval('(uint64_t)__myst_kernel_args.fdmappings_size'))
        mman_tracker.process_ownership_vec = int(gdb.parse_and_eval('(uint64_t)__myst_kernel_args.mman_pids_data'))
        mman_tracker.process_ownership_vec_size = int(gdb.parse_and_eval('(uint64_t)__myst_kernel_args.mman_pids_size'))
        mman_tracker.prot_vector = int(gdb.parse_and_eval('(uint64_t)_mman->prot_vector'))
        mman_tracker.vad_list_ptr = int(gdb.parse_and_eval('(uint64_t)&_mman->vad_list'))
        
        print("mman base= %x start=%x end=%x size=%d vad_list_ptr=%x" % (mman_tracker.mman_base, mman_tracker.mman_start, mman_tracker.mman_end, mman_tracker.mman_size, mman_tracker.vad_list_ptr))

        print("file_map_vec= 0x%x ownership_vec= 0x%x prot_vector=0x%x" % (mman_tracker.file_mappings_vec, mman_tracker.process_ownership_vec, mman_tracker.prot_vector))

        # Continue execution.
        return False

class MystMmanTracker:

    def __init__(self):
        self._welcome()

    # Dispatch the command
    def dispatch(self, arg0, *args):
        if arg0 == "-p":
            self._dump_maps_by_pids(*args)
        elif arg0 == "-h":
            self._help()
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
            '    Print help\n' \
            '  \033[0;32mmyst-mman [-p] <pid>\033[0m\n' \
            '  \033[0;32mmyst-mman [-d]\033[0m\n' \
            '    Dump memory data structures\n'
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
        print("start_addr=0x%x end_addr=0x%x size=%d" % (vad.addr, vad.addr + vad.size, vad.size))
 
    '''
    pids and fd mapping vectors track pages starting mman_base.
    prot vector tracks pages starting mman_start
    |guard page|mman_base|....|mman_start|...|mman_end|guard page|
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

    def _get_map_by_addr(self, addr_str, get_all=None):
        # Evaluate the address expression.
        addr = int(gdb.parse_and_eval(addr_str))
        print('address: %s = 0x%x' % (addr_str, addr))

        if not self._is_valid_heap_addr_range(addr, 0):
            print('invalid address!! Not in mman controlled region.')
            return

        index = self._get_pids_or_fd_index(addr)
        addr_pids_entry = self._get_pids_by_index(index)
        addr_fd_entry = self._get_fdmapping_by_index(index)
        addr_prot_entry = self._get_prot_by_index(self._get_prot_vec_index(addr))
        
        if not addr_pids_entry:
            ''' 
            addr lies either in shared memory, kernel owned or unallocated region.
            For shared memory, parse shared memory list.
            For kernel owned, there should be a corresponding VAD node.
            '''
            print("no pids entry")
            return
        
        # if we are here, this is a MAP_PRIVATE mapping
        '''
        scan left on both fd, prot and pids vec
        '''
        lowest_idx = self._get_pids_or_fd_index(mman_tracker.mman_start)
        tmp_index = index
        while tmp_index >= lowest_idx:
              if self._get_pids_by_index(tmp_index) == addr_pids_entry:
                fd_entry = self._get_fdmapping_by_index(index)
                if not addr_fd_entry.used == fd_entry.used:
                    break
                if not mman_file_handle_t.equal(mman_file_handle_t(addr_fd_entry.mman_file_handle), mman_file_handle_t(fd_entry.mman_file_handle)):
                    break
                if not addr_prot_entry == self._get_prot_by_addr(self._pids_index_to_addr(tmp_index)):
                    break
                tmp_index -= 1
        # while loop stops when either file, prot, pids property has changed.
        # So the start index is the page right of tmp_index.
        map_start_pids_idx = tmp_index + 1
        map_start_addr = self._pids_index_to_addr(map_start_pids_idx)

        '''
        scan right on both fd, prot and pids vec
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

        print("map_start_addr=0x%x map_end_addr=0x%x size=%d(0x%x)" % (map_start_addr, map_end_addr, map_size, map_size))
        print("Owning process: %d" % (addr_pids_entry))
        if addr_fd_entry.used == FDMAPPING_USED_MAGIC:
            print("File mapping info: offset=%d filesz=%d" % (addr_fd_entry.offset - (index - map_start_pids_idx)*4096, addr_fd_entry.filesz))
        print("Page protection = %s" % (self._prot_to_string(addr_prot_entry)))

        vad = self._lookup_vad_list(addr)
        if vad:
            print("VAD info for addr=0x%x:" % (addr))
            self._print_vad(vad)

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
