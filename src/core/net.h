#ifndef WIREHUB_NET_H
#define WIREHUB_NET_H

#include "common.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>

#define IP4_HDRLEN 20
#define UDP_HDRLEN 8

struct address {
    int sa_family;
    union {
        struct sockaddr in;
        struct sockaddr_in in4;
        struct sockaddr_in6 in6;
    };
};

static inline uint16_t address_port(const struct address* a) {
    switch (a->sa_family) {
    case AF_INET: return ntohs(a->in4.sin_port);
    case AF_INET6: return ntohs(a->in6.sin6_port);
    default: return 0;
    };
}

int parse_address(struct address* a, const char* endpoint, uint16_t port);
const char* format_address(const struct address* a, char* s, size_t sl);
int address_from_sockaddr(struct address* out, const struct sockaddr* in);
socklen_t address_len(const struct address* a);
void orchid(struct address* a, const void* cid, size_t cid_sz, const void* m, size_t l, uint16_t port);

int socket_udp(const struct address* a);
int socket_raw_udp(sa_family_t sa_family, int hdrincl);
int ip4_to_udp(const void* d, const void** pdata, size_t* psize, struct address* src, struct address* dst);

enum sniff_proto {
    SNIFF_PROTO_WG,
    SNIFF_PROTO_WH,
};

pcap_t* sniff(const char* interface, pcap_direction_t direction,  enum sniff_proto proto, const char* expr);

uint16_t checksum_ip(const void* addr, int len);

#endif  // WIREHUB_NET_H

