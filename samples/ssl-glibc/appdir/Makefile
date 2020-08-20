LDFLAGS = -lmbedtls -lmbedx509 -lmbedcrypto

all:
	gcc -g -fPIC $(INCLUDES) -o ssl_server ssl_server.c $(LDFLAGS)
	gcc -g -fPIC $(INCLUDES) -o ssl_client1 ssl_client1.c $(LDFLAGS)

clean:
	rm -f ssl_server
	rm -f ssl_client1
