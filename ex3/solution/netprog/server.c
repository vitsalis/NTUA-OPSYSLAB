#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "protocol.h"

void add_to_pfds(struct pollfd **pfds, int newfd, int *fd_count, int *fd_size) {
    if (*fd_count == *fd_size) {
        *fd_size *= 2;
        *pfds = realloc(*pfds, sizeof(**pfds) * *fd_size);
    }

    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events = POLLIN;

    (*fd_count)++;
}

void del_from_pfds(struct pollfd **pfds, int i, int *fd_count) {
    int n = *fd_count;
    (*pfds)[i] = (*pfds)[n - 1];
    *fd_count -= 1;
}

int get_listener_socket(void) {
    int listener;
    int yes = 1;
    int rv;
    struct addrinfo hints, *ai, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // don't care whether IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // stream socket
    hints.ai_flags = AI_PASSIVE; // get the host's address

    if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) == -1) {
        fprintf(stderr, "couldn't get address info %s", gai_strerror(rv));
        exit(1);
    }

    for (p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener == -1) {
            perror("socket");
            continue;
        }

        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            perror("bind");
            close(listener);
            continue;
        }
        break;
    }
    if (p == NULL) {
        return -1;
    }
    freeaddrinfo(ai);
    if (listen(listener, MAXCONN) == -1) {
        perror("listen");
        close(listener);
        return -1;
    }

    return listener;
}

int main(int argc, char **argv) {
    int listener; // Listening socket descriptor

    int newfd; // Newly accepted socket descriptor
    struct sockaddr_storage remoteaddr; // client address
    socklen_t addrlen;

    char buf[MAXDATASIZE]; // buffer for client data
    char remoteIP[INET6_ADDRSTRLEN]; // buffer for client ip address

    // Start off with room for 5 connections
    // will realloc as necessary
    int fd_count = 0;
    int fd_size = 5;
    struct pollfd *pfds = malloc(sizeof *pfds * fd_size);

    listener = get_listener_socket();

    if (listener == -1) {
        fprintf(stderr, "error getting listening socket");
        exit(1);
    }

    pfds[0].fd = listener;
    pfds[0].events = POLLIN; // Report ready on incomming connection
    fd_count = 1;

    while (1) {
        int poll_count = poll(pfds, fd_count, -1);

        if (poll_count == -1) {
            perror("poll");
            exit(1);
        }

        for (int i = 0; i < fd_count; ++i) {
             if (pfds[i].revents & POLLIN) { // we got one
                if (pfds[i].fd == listener) { // new connection
                    addrlen = sizeof remoteaddr;
                    newfd = accept(listener, (struct sockaddr*) &remoteaddr, &addrlen);

                    if (newfd == -1) {
                        perror("accept");
                        continue;
                    }

                    add_to_pfds(&pfds, newfd, &fd_count, &fd_size);
                    printf("pollserver: new connection from %s on socket %d\n",
                        inet_ntop(remoteaddr.ss_family, get_in_addr((struct sockaddr*)&remoteaddr), remoteIP, INET6_ADDRSTRLEN),
                        newfd);
                }
                else { // a client
                    int nbytes;
                    recvall(pfds[i].fd, buf, &nbytes, MAXDATASIZE);

                    if (nbytes <= 0) { // client disconnected
                        if (nbytes == 0) {
                            printf("pollserver: socket %d hung up\n", pfds[i].fd);
                        }
                        else {
                            perror("recv");
                        }
                        close(pfds[i].fd);
                        del_from_pfds(&pfds, i, &fd_count);
                    }
                    else { // new message
                        for (int j = 0; j < fd_count; ++j) {
                            if (pfds[j].fd != pfds[i].fd && pfds[j].fd != listener) {
                                if (sendall(pfds[j].fd, buf, nbytes) == -1) {
                                    perror("send");
                                }
                            }
                        }
                    }
                }
             }
        }
    }

    return 0;
}
