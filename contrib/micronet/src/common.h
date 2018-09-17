#ifndef MICRONET_COMMON_H
#define MICRONET_COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "config.h"

#define ERROR(func)    \
    fprintf(stderr, func " error: %s (%s:%d)\n", strerror(errno), __FILE__, __LINE__)

#define UNET_STR(x)    UNET_STR_(x)
#define UNET_STR_(x)    #x

#define LOG(...)    fprintf(stderr, __VA_ARGS__)
#define LOG_SOCKADDR(addr)  \
    do { \
        char addr_s[INET_ADDRSTRLEN+1]; \
        inet_ntop(AF_INET, &(addr)->sin_addr,addr_s, sizeof(addr_s)-1); \
        LOG("%s:%d", addr_s, ntohs((addr)->sin_port)); \
    } while(0)

#define LOG_ADDR(addr)  \
    do { \
        char addr_s[INET_ADDRSTRLEN+1]; \
        inet_ntop(AF_INET, addr, addr_s, sizeof(addr_s)-1); \
        LOG("%s", addr_s); \
    } while(0)


#endif  // MICRONET_COMMON_H

