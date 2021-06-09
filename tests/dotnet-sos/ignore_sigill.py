'''
Originally from https://github.com/rwestberg/lldbscripts
'''
import lldb
import threading

SIGILL_NUM = 4
class ProcessEventListener(threading.Thread):
    def __init__(self, debugger):
        super(ProcessEventListener, self).__init__()
        self._listener = debugger.GetListener()
        self._debugger = debugger
        self._interpreter = debugger.GetCommandInterpreter()
        self._handled = set()
    
    def _suppress_signals(self, process):
        signals = process.GetUnixSignals()
        signals.SetShouldStop(SIGILL_NUM, False)
        signals.SetShouldNotify(SIGILL_NUM, False)

    def run(self):
        while True:
            event = lldb.SBEvent()
            if not self._listener.PeekAtNextEvent(event):
                continue                
            process = self._interpreter.GetProcess()
            if process and not process.GetUniqueID() in self._handled:
                self._suppress_signals(process)
                self._handled.add(process.GetUniqueID())

def __lldb_init_module(debugger, *rest):
    listener_thread = ProcessEventListener(debugger)
    listener_thread.start()
