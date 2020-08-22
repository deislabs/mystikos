all:
	gcc -g -fPIC -Wall -o main main.c -ldl
	gcc -g -fPIC -Wall -shared -o libfoo.so foo.c -ldl
	gcc -g -fPIC -Wall -shared -o libbar.so bar.c -ldl

clean:
	rm -rf main libfoo.so libbar.so
