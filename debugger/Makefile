TOP=$(abspath $(CURDIR)/..)

BUILDDIR=${TOP}/build

all: ${BUILDDIR}/bin/myst-gdb \
	${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mprotect.py \
	${BUILDDIR}/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py \
	${BUILDDIR}/lib/debugger/gdb-sgx-plugin/print.py \
	${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mman.py \

${BUILDDIR}/bin/myst-gdb:
	rm -f ${BUILDDIR}/bin/myst-gdb
	cp ${CURDIR}/myst-gdb ${BUILDDIR}/bin/myst-gdb

${BUILDDIR}/lib/debugger/gdb-sgx-plugin:
	mkdir -p ${BUILDDIR}/lib/debugger/gdb-sgx-plugin

${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mprotect.py: ${BUILDDIR}/lib/debugger/gdb-sgx-plugin
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mprotect.py
	cp ${CURDIR}/gdb-sgx-plugin/mprotect.py ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mprotect.py

${BUILDDIR}/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py: ${BUILDDIR}/lib/debugger/gdb-sgx-plugin
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py
	cp ${CURDIR}/gdb-sgx-plugin/symbol_analyzer.py ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py

${BUILDDIR}/lib/debugger/gdb-sgx-plugin/print.py: ${BUILDDIR}/lib/debugger/gdb-sgx-plugin
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/print.py
	cp ${CURDIR}/gdb-sgx-plugin/print.py ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/print.py

${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mman.py: ${BUILDDIR}/lib/debugger/gdb-sgx-plugin
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mman.py
	cp ${CURDIR}/gdb-sgx-plugin/mman.py ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mman.py

clean:
	rm -f ${BUILDDIR}/bin/myst-gdb
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mprotect.py
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/symbol_analyzer.py
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/print.py
	rm -f ${BUILDDIR}/lib/debugger/gdb-sgx-plugin/mman.py

distclean: clean
	rm -rf ${BUILDDIR}/lib/debugger
