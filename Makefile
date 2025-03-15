cc = gcc
flags = -wall -pthread -lcrypto

all: build

build: server client

server: server.c
	$(cc) $(cflags) -o server server.c -pthread -lcrypto

client: client.c
	$(cc) $(cflags) -o client client.c -lcrypto

run:
	./server & sleep 1 && ./client

clean:
	rm -f server client
