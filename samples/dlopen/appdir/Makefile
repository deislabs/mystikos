
all:
	mkdir -p bin
	mkdir -p lib
	gcc -Wall -o ./bin/main main.c -ldl
	gcc -Wall -shared -o ./lib/libfoo.so foo.c -ldl

clean:
	rm -rf bin lib
