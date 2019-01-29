#include "net.h"
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int parse_address(struct address* a, const char* endpoint, uint16_t port, int numeric) {
    struct addrinfo hint, *res = NULL;
    int ret;

    if (!endpoint) {
        return -1;
    }

    const char* addr_s = endpoint,* addr_end = NULL;
    // ip6?
    if (addr_s[0] == '[') {
        ++addr_s;
        const char* e = strchr(addr_s, ']');
        if (!e) {
            return -1;
        }

        addr_end = e;
    }

    // ip4?
    else if ('0' <= addr_s[0] && addr_s[0] <= '9') {
        addr_end = strchr(addr_s, ':');
        if (!addr_end) addr_end = addr_s + strlen(addr_s);
    }

    else {
        addr_end = strchr(addr_s, ':');
        if (!addr_end) addr_end = addr_s + strlen(addr_s);
    }

    const char* port_s = strrchr(endpoint, ':');
    // ignore : from the ip6 string
    if (port_s && port_s < addr_end) {
        port_s = NULL;
    }

    if (port_s) {
        int port_i = atoi(port_s+1);

        if (port_i < 0 || UINT16_MAX < port_i) {
            return -1;
        }

        port = (uint16_t)port_i;
    }

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = AI_PASSIVE; // XXX why?

    if (numeric) {
        hint.ai_flags |= AI_NUMERICHOST;
    }

    char* addr = alloca(addr_end-addr_s+1);
    memcpy(addr, addr_s, addr_end-addr_s);
    addr[addr_end-addr_s] = 0;

    if ((ret = getaddrinfo(addr, NULL, &hint, &res))) {
        // more info gai_strerror(ret)
        return -1;
    }

    a->sa_family = res->ai_family;

    if(res->ai_family == AF_INET) {
        a->in4 = *(struct sockaddr_in*)res->ai_addr;
        a->in4.sin_port = htons(port);
    }

    else if (res->ai_family == AF_INET6) {
        a->in6 = *(struct sockaddr_in6*)res->ai_addr;
        a->in6.sin6_port = htons(port);
    }

    else {
        // "unknown address format %d\n",argv[1],res->ai_family);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}

socklen_t address_len(const struct address* a) {
    switch (a->sa_family) {
    case AF_INET:  return sizeof(struct sockaddr_in);
    case AF_INET6: return sizeof(struct sockaddr_in6);
    default:       return 0;
    };
}

const char* format_address(const struct address* a, char* s, size_t sl) {
    assert(s);
    assert(a);

    // s needs to be at least 47
    // example: [e0be:b85d:88ed:6c3b:a1aa:3f57:ab3:c850]:65535

    socklen_t inl = address_len(a);
    if (inl == 0) {
        return NULL;
    }

    switch (a->sa_family) {
    case AF_INET:
        if (!inet_ntop(a->sa_family, &a->in4.sin_addr, s, sl-1)) {
            return NULL;
        }
        break;

    case AF_INET6:
        s[0] = '[';
        if (!inet_ntop(a->sa_family, &a->in6.sin6_addr, s+1, sl-2)) {
            return NULL;
        }
        strcat(s, "]");
        break;
    default:
        return NULL;
    };

    char buf[8];
    snprintf(buf, sizeof(buf), ":%d", address_port(a));
    strncat(s, buf, sl);

    return s;
}

int address_from_sockaddr(struct address* out, const struct sockaddr* in) {
    switch (*(sa_family_t*)in) {
    case AF_INET:
        out->sa_family = AF_INET;
        out->in4 = *(struct sockaddr_in*)in;
        break;

    case AF_INET6:
        out->sa_family = AF_INET6;
        out->in6 = *(struct sockaddr_in6*)in;
        break;

    default:
        return -1;
    };

    return 0;
}




int socket_udp(const struct address* a) {
    int s = socket(a->sa_family, SOCK_DGRAM, 0);
    if (s == -1) {
        return -1;
    }

    if (fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) == -1) {
        close(s);
        return -1;
    }

    if (bind(s, &a->in, address_len(a)) == -1) {
        close(s);
        return -1;
    }

    return s;
}

int socket_raw_udp(sa_family_t sa_family, int hdrincl) {
    int s = socket(sa_family, SOCK_RAW, IPPROTO_UDP);
    if (s == -1) {
        return -1;
    }

    /*if (fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK) == -1) {
        close(s);
        return -1;
    }*/

    if (hdrincl) {
        int on = 1;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            close(s);
            return -1;
        }
    }

    return s;
}

int ip4_to_udp(const void* d, const void** pdata, size_t* psize, struct address* src, struct address* dst) {
    assert(d && psize);
    // src and dst may be NULL

    const void* p = d;

    if (*psize < 1) {
        return -1;
    }

#define IPHDR   ((struct ip*)(p))
    size_t ip_hdr_sz = IPHDR->ip_hl*sizeof(uint32_t);
    if (*psize < ip_hdr_sz) {
        return -1;
    }

    if (IPHDR->ip_p != IPPROTO_UDP) {
        return -1;
    }

    if (src) {
        src->sa_family = src->in4.sin_family = AF_INET;
        memcpy(&src->in4.sin_addr, &IPHDR->ip_src, 4);
    }

    if (dst) {
        dst->sa_family = dst->in4.sin_family = AF_INET;
        memcpy(&dst->in4.sin_addr, &IPHDR->ip_dst, 4);
    }

#undef IPHDR

    p += ip_hdr_sz;

    // XXX do IP6
    const int udp_hdr_sz = 8;

    if (*psize < ip_hdr_sz+udp_hdr_sz) {
        return -1;
    }

#define UDPHDR  ((struct udphdr*)(p))

    // XXX should check checksum?

    if (src) {
        switch (src->sa_family) {
        case AF_INET:  src->in4.sin_port = UDPHDR->uh_sport; break;
        case AF_INET6: src->in6.sin6_port = UDPHDR->uh_sport; break;
        };
    }

    if (dst) {
        switch(dst->sa_family) {
        case AF_INET:  dst->in4.sin_port = UDPHDR->uh_dport; break;
        case AF_INET6: dst->in6.sin6_port = UDPHDR->uh_dport; break;
        };
    }


    uint16_t udp_sz = ntohs(UDPHDR->uh_ulen);
    if (udp_sz < udp_hdr_sz) {
        return -1;
    }

    if (*psize < ip_hdr_sz+udp_sz) {
        fprintf(stderr, "WARNING: *psize:%d, ip_hdr_sz:%d udp_sz:%d\n",
                (int)*psize, (int)ip_hdr_sz, (int)udp_sz
        );

        FILE* fh = fopen("/tmp/packet.buf", "wb");
        fwrite(d, *psize, 1, fh);
        fclose(fh);

        return -1;
    }

#undef UDPHDR

    p += udp_hdr_sz;

    *pdata = p;
    *psize = udp_sz-udp_hdr_sz;

    return 0;
}

uint16_t checksum_ip(const void* buf_, int count) {
    register uint32_t sum = 0;
    uint16_t answer = 0;
    const uint16_t* buf = buf_;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(buf++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) buf;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return answer;
}

