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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "protocol.h"

void add_pad(char *buf) {
    for (int i = strlen(buf) + 1; i < MAXDATASIZE; ++i) {
        buf[i] = '\0';
    }
}

int get_server_socket(char *host) {
    int rv, sockfd;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(host, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client:socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client:connect");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "client: couldn't connect to server\n");
        exit(1);
    }

    return sockfd;
}

int main(int argc, char **argv) {
    int server, numbytes, fd_count = 2, cfd;
    unsigned int sid;
    size_t size;
    char *received, *sent, *key, *device;
    char *buf;
    struct pollfd pfds[fd_count];

    if (argc < 3) {
        fprintf(stderr, "usage: client hostname key [device]\n");
        exit(1);
    }

    received = (char *)malloc(sizeof(char) * MAXDATASIZE);
    sent = (char *)malloc(sizeof(char) * MAXDATASIZE);
    buf = (char *)malloc(sizeof(char) * MAXDATASIZE);

    server = get_server_socket(argv[1]);
    key = argv[2];
    device = (argv[3] == NULL) ? "/dev/crypto" : argv[3];

    cfd = open(device, O_RDWR);
    if (cfd < 0) {
	    perror(device);
	    exit(1);
    }

    sid = create_session(cfd, key);

    pfds[0].fd = STDIN_FILENO;
    pfds[0].events = POLLIN;
    pfds[1].fd = server;
    pfds[1].events = POLLIN;

    while (1) {
        int poll_count = poll(pfds, 2, -1);
        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        for (int i = 0; i < fd_count; ++i) {
            if (pfds[i].revents & POLLIN) {
                if (pfds[i].fd == STDIN_FILENO) { // client sent a message
                    getline(&sent, &size, stdin);
		    encrypt(sent, buf, cfd, sid);
                    add_pad(buf);

                    if (sendall(server, buf, MAXDATASIZE) == -1) {
                        perror("send");
                        exit(1);
                    }
                }
                if (pfds[i].fd == server) { // client received a message
                    recvall(server, received, &numbytes, MAXDATASIZE);
                    if (numbytes <= 0) {
                        if (numbytes == 0) {
                            printf("Server hung up.\n");
                        }
                        else {
                            perror("recv");
                        }
                        exit(1);
                    }
		    decrypt(received, buf, cfd, sid);
                    printf("%s", buf);
                }
            }
        }
    }

    close_session(cfd, sid);
    close(cfd);

    close(server);
    return 0;
}
