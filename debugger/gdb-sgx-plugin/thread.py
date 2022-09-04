import gdb
import math
import tempfile
from typing import List

DEBUG = False

INSTANCE_DEBUG_EXT = None

class ThreadCreateBreakpoint(gdb.Breakpoint):
    
    STR_FIRST_ARG = "((struct run_thread_arg*)$rdi)"

    def __init__(self):
        """
        Set a breakpoing @ kernel/thread.c:_run_thread, this should be right before myst_setjmp(&thread->jmpbuf)
        Choosing this location because this is where the newly created thread about to run
        We can get the new thread pid/tid here
        """
        super(ThreadCreateBreakpoint, self).__init__('kernel/thread.c:_run_thread', internal=False)

    def stop(self):
        # New thread info
        ppid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->thread->process->ppid'))
        pid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->thread->process->pid'))
        tid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->thread->tid'))
        tid_target = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->target_tid'))
        if DEBUG:
            print("Created thread: ppid, pid, tid, tid_target", ppid, pid, tid, tid_target)
        INSTANCE_DEBUG_EXT.add_thread(pid, tid, ppid, tid_target)

        # Add _main_thread only once as it won't change often
        if not INSTANCE_DEBUG_EXT.main_thread_tracked():
            main_ppid = int(gdb.parse_and_eval('_main_thread->process->ppid'))
            main_pid = int(gdb.parse_and_eval('_main_thread->process->pid'))
            main_tid = int(gdb.parse_and_eval('_main_thread->tid'))
            main_tid_target = int(gdb.parse_and_eval('_main_thread->target_tid'))
            if DEBUG:
                print("Main thread: ppid, pid, tid, tid_target", main_ppid, main_pid, main_tid, main_tid_target)
            INSTANCE_DEBUG_EXT.add_thread(main_pid, main_tid, main_ppid, main_tid_target)

        INSTANCE_DEBUG_EXT.copy_parent_process(pid, ppid)
        return False

class ThreadExitBreakpoint(gdb.Breakpoint):

    STR_FIRST_ARG = "((const myst_thread_t*)$rdi)"

    def __init__(self):
        """
        Set a breakpoint @ kernel/thread.c:myst_debug_hook_thread_exit, where myst_setjmp returns non-zero
        Choosing this location because this is where the thread terminates
        """
        super(ThreadExitBreakpoint, self).__init__('kernel/thread.c:myst_debug_hook_thread_exit', internal=False)

    def stop(self):
        # Get thread info that is about to terminate
        ppid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->process->ppid'))
        pid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->process->pid'))
        tid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->tid'))
        tid_target = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->target_tid'))
        if DEBUG:
            print("Exit thread: ppid, pid, tid, tid_target", ppid, pid, tid, tid_target)

        INSTANCE_DEBUG_EXT.remove_thread(tid)
        return False

class MystExecBreakpoint(gdb.Breakpoint):

    STR_FIRST_ARG = "((const myst_thread_t*)$rdi)"
    STR_THIRD_ARG = "((const char**)$rdx)"

    def __init__(self):
        """
        Obtain program's name, args and cwd to use in enclave
        """
        super(MystExecBreakpoint, self).__init__('kernel/exec.c:myst_debug_hook_myst_exec', internal=False)

    def parse_string_raw(self, str_raw):
        """
        Parse the string given the gdb parse_and_eval result

        Example input:
        0x104df31f0 "/bin/usr/some/path"

        Example return:
        /bin/usr/some/path
        """
        val = str(str_raw)
        if ' ' not in val:
            return val
        
        # Don't include "
        return val[val.index(' ') + 2:-1]

    def stop(self):
        # Same as parse and eval *argv@argc
        argc = int(gdb.parse_and_eval('$rsi'))

        # ((const char**)$rdx)[0..1..2..]
        argv_raw = [gdb.parse_and_eval('{0}[{1}]'.format(self.STR_THIRD_ARG, i)) for i in range(argc)]
        cwd_raw = gdb.parse_and_eval(self.STR_FIRST_ARG + '->process->cwd')

        argv = [self.parse_string_raw(each) for each in argv_raw]
        cwd = self.parse_string_raw(cwd_raw)

        # Get pid and ppid
        ppid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->process->ppid'))
        pid = int(gdb.parse_and_eval(self.STR_FIRST_ARG + '->process->pid'))

        INSTANCE_DEBUG_EXT.set_process_cmd_cwd(pid, ppid, argv, cwd)

        return False

class DebugExtension:
    """
    Manage all breakpoints and program info(process/thread/cmdline/etc)
    """

    # Configure the default pid/tid for the main process
    # We only gather _main_thread's information once
    tid_main_thread = 101

    def __init__(self):
        self.bp_thread_create = ThreadCreateBreakpoint()
        self.bp_thread_exit = ThreadExitBreakpoint()
        self.bp_myst_exec = MystExecBreakpoint()

        self.map_commands = {
            'help': lambda: self._command_help(),
            'thread': lambda: self._command_list_thread(),
            'cmdline': lambda: self._command_cmdline(),
            'exe': lambda: self._command_exe(),
            'cwd': lambda: self._command_cwd()
        }

        # Store thread info
        # Key: tid
        # Value: tuple (pid, tid, ppid, tid_target)
        self.threads = dict()

        # Store process info
        # Key: pid
        # Value: tuple (pid, ppid, command line, cwd)
        # where command line should be list of string
        self.processes = dict()

        self.clear()

    def main_thread_tracked(self):
        return self.tid_main_thread in self.threads

    def add_thread(self, pid: int, tid: int, ppid: int, tid_target: int):
        """
        ppid: parent pid
        tid_target: tid on host
        """
        self.threads[tid] = (pid, tid, ppid, tid_target)
    
    def remove_thread(self, tid: int):
        if tid not in self.threads:
            print("DebugExtension Error: trying to remove non-exist thread ", tid)
            return
        del self.threads[tid]

    def copy_parent_process(self, pid, ppid):
        """
        When a new process is created, copy the cmdline from its parent
        """
        if pid in self.processes:
            if DEBUG:
                print("Unexpected: pid {0} should not exist in self.processes".format(pid))
            return
        
        if ppid not in self.processes:
            # Parent process might have already exited
            return

        _, _, cmdline, cwd = self.processes[ppid]
        self.processes[pid] = (pid, ppid, cmdline, cwd)
        if DEBUG:
            print("Copied", self.processes[pid])

    def set_process_cmd_cwd(self, pid: int, ppid: int, argv: List[int], cwd: str):
        self.processes[pid] = (pid, ppid, argv, cwd)

    def clear(self):
        self.threads = dict()
        self.processes = dict()

    def dispatch(self, command: str):
        if command not in self.map_commands:
            print("DebugExtension Error: Invalid command, should be one of ", sorted(list(self.map_commands.keys())))
            return

        self.map_commands[command]()

    def _command_help(self):
        msg = """
myst-thread: Mystikos thread tracker
Commands:
myst-thread help
    Print this message

myst-thread thread
    List all tracked threads

myst-thread cmdline
    List the command line for each process

myst-thread exe
    List the executable for each process

myst-thread cwd
    List the current working directory for each process
"""
        print(msg)

    def _command_list_thread(self):
        if not self.threads:
            print("No threads tracked")
            return

        print("List of Mystikos controlled threads:")
        print("ppid pid tid (target_tid)")
        for key in sorted(self.threads.keys()):
            pid, tid, ppid, target_tid = self.threads[key]
            print("{0} {1} {2} ({3})".format(ppid, pid, tid, target_tid))

    def _command_cmdline(self):
        """
        Similiar to gdb command 'info proc cmdline'
        """
        if not self.processes:
            print("No processes tracked")
            return

        for pid in sorted(self.processes.keys()):
            pid, ppid, cmdline, _ = self.processes[pid]
            print("Process {0} (Parent {1}) cmdline: {2}".format(pid, ppid, " ".join(cmdline)))

    def _command_exe(self):
        """
        Similiar to gdb command 'info proc exe'
        """
        if not self.processes:
            print("No processes tracked")
            return

        for pid in sorted(self.processes.keys()):
            pid, ppid, cmdline, _ = self.processes[pid]
            print("Process {0} (Parent {1}) exe: {2}".format(pid, ppid, cmdline[0]))

    def _command_cwd(self):
        """
        Similiar to gdb command 'info proc cwd'
        """
        if not self.processes:
            print("No processes tracked")
            return

        for pid in sorted(self.processes.keys()):
            pid, ppid, _, cwd = self.processes[pid]
            print("Process {0} (Parent {1}) cwd: {2}".format(pid, ppid, cwd))

command = """
define myst-thread
  if $argc == 0
      python INSTANCE_DEBUG_EXT.dispatch("help")
  end
  if $argc == 1
      python INSTANCE_DEBUG_EXT.dispatch("$arg0")
  end
end
"""

if __name__ == "__main__":
    INSTANCE_DEBUG_EXT = DebugExtension()

    # Register command with gdb.
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(command)
        f.flush()
        gdb.execute('source %s' % f.name)

    # Register exit_handler
    def exit_handler(event):
       global INSTANCE_DEBUG_EXT
       INSTANCE_DEBUG_EXT.clear()
    gdb.events.exited.connect(exit_handler)
