all:
	gcc -g -fPIC -Wall -o main main.c -ldl
	gcc -g -fPIC -Wall -shared -o libfoo.so foo.c -ldl

clean:
	rm -rf libfoo.so main
