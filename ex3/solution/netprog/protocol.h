#ifndef _CHAT_PROTOCOL_H
#define _CHAT_PROTOCOL_H

#define PORT "3993"
#define MAXDATASIZE 256
#define BLOCK_SIZE 24
#define MAXCONN 10

void recvall(int fd, char *buf, int *numbytes, int len);
int sendall(int fd, char* buf, int len);
void *get_in_addr(struct sockaddr *sa);
void encrypt(char *source, char *dest, int cfd, unsigned int sid);
void decrypt(char *source, char *dest, int cfd, unsigned int sid);
unsigned int create_session(int cfd, char *key);
void close_session(int cfd, unsigned int sid);

#endif
