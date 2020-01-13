CC = gcc
USER_CFLAGS = -Wall -Werror
OBJECT_FLAGS = -c
PROTOCOL_OBJECT = protocol.o

all: server client

server: protocol
	$(CC) $(USER_CFLAGS) $(OBJECT_FLAGS) server.c
	$(CC) $(PROTOCOL_OBJECT) server.o -o server

client: protocol
	$(CC) $(USER_CFLAGS) $(OBJECT_FLAGS) client.c
	$(CC) $(USER_CFLAGS) $(OBJECT_FLAGS) client_encrypted.c
	$(CC) $(PROTOCOL_OBJECT) client.o -o client
	$(CC) $(PROTOCOL_OBJECT) client_encrypted.o -o client_encrypted

protocol:
	$(CC) $(USER_CFLAGS) $(OBJECT_FLAGS) protocol.c
