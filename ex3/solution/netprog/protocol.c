#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <arpa/inet.h>
#include <crypto/cryptodev.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "protocol.h"

void recvall(int fd, char *buf, int *numbytes, int len) {
    int total = 0;
    int bytesleft = len;
    int n;
    while (total < len) {
        n = recv(fd, buf + total, len, 0);
        if (n <= 0) {
            *numbytes = n;
            return;
        }
        total += n;
        bytesleft -= n;
    }
    *numbytes = total;
}

int sendall(int fd, char* buf, int len) {
    int total = 0;
    int bytesleft = len;
    int n;

    while (total < len) {
        n = send(fd, buf + total, bytesleft, 0);
        if (n == -1) {
            return -1;
        }
        total += n;
        bytesleft -= n;
    }
    return 0;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

unsigned int create_session(int cfd, char *key) {
	struct session_op sess;

	memset(&sess, 0, sizeof(sess));

	sess.cipher = CRYPTO_AES_CBC;
	sess.key = (unsigned char *)key;
	sess.keylen = strlen(key);

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}

	return sess.ses;
}

void close_session(int cfd, unsigned int sid) {
	/* Finish crypto session */
	if (ioctl(cfd, CIOCFSESSION, &sid)) {
		perror("ioctl(CIOCFSESSION)");
		exit(1);
	}
}

void setup_iv(unsigned char *iv) {
	memcpy(iv, "thisisnotrandom", 15);
}

void encrypt(char *source, char *dest, int cfd, unsigned int sid) {
	struct crypt_op cryp;
	unsigned char *iv = malloc(sizeof(unsigned char) * BLOCK_SIZE);

	setup_iv(iv);

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sid;
	cryp.len = MAXDATASIZE;
	cryp.src = (unsigned char *)source;
	cryp.dst = (unsigned char *)dest;
	cryp.iv = iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}
}

void decrypt(char *source, char *dest, int cfd, unsigned int sid) {
	struct crypt_op cryp;
	unsigned char *iv = malloc(sizeof(unsigned char) * BLOCK_SIZE);

	setup_iv(iv);
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sid;
	cryp.len = MAXDATASIZE;
	cryp.src = (unsigned char *)source;
	cryp.dst = (unsigned char *)dest;
	cryp.iv = iv;
	cryp.op = COP_DECRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}
}
