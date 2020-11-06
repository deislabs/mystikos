
all:
	gcc -g -fPIC -o ssl_server ssl_server.c -lmbedtls -lmbedx509 -lmbedcrypto
	gcc -g -fPIC -o ssl_client1 ssl_client1.c -lmbedtls -lmbedx509 -lmbedcrypto
	gcc -g -fPIC -o ssl ssl.c

clean:
	rm -f ssl_server
	rm -f ssl_client1
	rm -f ssl
