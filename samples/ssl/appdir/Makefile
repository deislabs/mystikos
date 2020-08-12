
all:
	gcc -g -fPIC -o ssl_server ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto
	gcc -g -fPIC -o ssl_client1 ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto

clean:
	rm -f ssl_server
	rm -f ssl_client1
