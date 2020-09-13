all:
	gcc -g -fPIC -Wall -o dlopen dlopen.c -ldl
	gcc -g -fPIC -Wall -shared -o libfoo.so foo.c -ldl
	gcc -g -fPIC -Wall -shared -o libbar.so bar.c -ldl

clean:
	rm -rf dlopen libfoo.so libbar.so
