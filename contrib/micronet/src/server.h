#ifndef MICRONET_SERVER_H
#define MICRONET_SERVER_H

#include "common.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include "conf.h"

extern struct timespec now;  // updated after each epoll_wait()

#define DROP(n,p,reason, ...) \
    do { \
        LOG("drop! " reason "\n",##__VA_ARGS__); \
        free(p); \
        return; \
    } while(0)


enum direction {
    UP = 0,
    DOWN = 1
};

struct packet {
    struct packet* next;
    size_t sz;
    enum direction dir;
    node_id from_id;
    union {
        struct {
            uint32_t id;
            union {
                uint8_t body[UNET_DEFAULT_MTU];
                struct ip hdr;
            };
        };
        uint8_t buf[sizeof(uint32_t)+UNET_DEFAULT_MTU];
    };
};

static inline void* packet_ip_payload(struct packet* p, size_t *psize) {
    size_t ip_hdr_sz = p->hdr.ip_hl*sizeof(uint32_t);
    if (psize) {
        *psize = p->sz - ip_hdr_sz;
    }
    return p->body+ip_hdr_sz;
}

struct nat_tcpudp {
    node_id id;
    time_t opened_ts;
    struct in_addr saddr;
    struct in_addr daddr;
    uint16_t sport;
    uint16_t dport;
};

struct nat_icmp {
    node_id id;
    time_t opened_ts;
    uint16_t siid;
    struct in_addr saddr;
};

#define NODE_ARGS(i)   (3+(i))
void sendto_id(struct node* from_n, node_id to_id, struct packet* p);
int _udp_sendto(struct sockaddr_in* peer_addr, struct iovec* iov, int iovlen);

int _peer(lua_State* L);
int _link(lua_State* L);
int _nat(lua_State* L);
int _wan(lua_State* L);

void packet_refresh_sum(struct packet* p);
void print_packet(FILE* fh, struct packet* p);

#endif  // MICRONET_SERVER_H

