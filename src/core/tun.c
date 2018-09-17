#include "luawh.h"
#include "net.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <netinet/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <unistd.h>


#define MT  "tun"

struct tun {
    char* interface;
    int fd;
};

static void delete_tun(struct tun* t) {
    if (t->fd >= 0) { close(t->fd), t->fd = -1; }
    if (t->interface) { free(t->interface), t->interface = NULL; }

    free(t);
}

static void delete_tun_pvoid(void* t) {
    return delete_tun((struct tun*)t);
}

int luaW_newtun(lua_State* L) {
    const char* interface = luaL_checkstring(L, 1);
    const char* subnet = luaL_checkstring(L, 2);
    int mtu = luaL_checkinteger(L, 3);

    if (mtu < 576) {
        luaL_error(L, "MTU too small");
    }

    struct tun* t = calloc(1, sizeof(struct tun));

    if ((t->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        delete_tun(t);
        luaL_error(L, "could not open \"/dev/net/tun\": %s", strerror(errno));
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (interface) {
        strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    }

    if (ioctl(t->fd, TUNSETIFF, (void *) &ifr) < 0) {
        delete_tun(t);
        luaL_error(L, "ioctl() failed: %s", strerror(errno));
    }

    t->interface = strdup(ifr.ifr_name);

    if (fcntl(t->fd, F_SETFL, fcntl(t->fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        delete_tun(t);
        luaL_error(L, "fcntl() failed: %s", strerror(errno));
    }

    // XXX
    {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ip link set dev %s mtu %d", t->interface, mtu);
        if (system(cmd) < 0) {
            delete_tun(t);
            luaL_error(L, "set mtu failed: %s", strerror(errno));
        }

        snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", subnet, t->interface);
        if (system(cmd) < 0) {
            delete_tun(t);
            luaL_error(L, "set address failed: %s", strerror(errno));
        }

        snprintf(cmd, sizeof(cmd), "ip link set %s up", t->interface);
        if (system(cmd) < 0) {
            delete_tun(t);
            luaL_error(L, "tun up failed: %s", strerror(errno));
        }
    }

    luaW_pushptr(L, MT, t);
    return 1;
}

static int _read(lua_State* L) {
    struct tun* t = luaW_checkptr(L, 1, MT);

    char pkt[2048];
    ssize_t r = read(t->fd, pkt, sizeof(pkt));

    if (r < 0 && errno == EAGAIN) {
        return 0;
    }

    if (r < 0) {
        luaL_error(L, "read error(): %s", strerror(errno));
    }

    if (r < 5) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "malformed packet");
        return 2;
    }

    /*
    const size_t tun_hdr_sz = 4;
    struct tun_pi* tun_hdr = (struct tun_pi*)pkt;
    tun_hdr->proto = ntohs(tun_hdr->proto);

    if (tun_hdr->proto != ETHERTYPE_IP) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "unknown protocol");
        return 2;
    }*/

    const struct ip* ip_hdr = (struct ip*)pkt;
    size_t ip_hdr_sz = ip_hdr->ip_hl*sizeof(uint32_t);
    if ((size_t)r < ip_hdr_sz) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "malformed IP header");
        return 2;
    }

    if (ip_hdr->ip_hl != 5) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "unhandled IP4 options");
        return 2;
    }

    size_t l = ntohs(ip_hdr->ip_len);
    if (l < ip_hdr_sz) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "malformed IP header");
        return 2;
    }
    l -= ip_hdr_sz;

    if (
        ip_hdr->ip_p != IPPROTO_UDP &&
        (!WH_TUN_ICMP || ip_hdr->ip_p != IPPROTO_ICMP)
    ) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "unhandled protocol: %d", ip_hdr->ip_p);
        return 2;
    }

    // IPv4 UDP fragmentation
    uint16_t ip_off = ntohs(ip_hdr->ip_off);
    if (ip_hdr->ip_p == IPPROTO_UDP &&
        (ip_off&IP_OFFMASK) == 0x0000
    ) {
        // packet contains UDP header
        if (l < UDP_HDRLEN) {
            lua_pushboolean(L, 0);
            lua_pushstring(L, "malformed UDP header");
            return 2;
        }

        struct udphdr* udp_hdr = (struct udphdr*)(pkt+ip_hdr_sz);
        udp_hdr->uh_sport = 0;
        udp_hdr->uh_dport = 0;
        udp_hdr->uh_sum = 0;
    }

    const void* m = pkt+ip_hdr_sz;

    lua_pushboolean(L, 1);

    struct address* src = luaW_newaddress(L);
    src->sa_family = src->in4.sin_family = AF_INET;
    memcpy(&src->in4.sin_addr, &ip_hdr->ip_src, 4);
    src->in4.sin_port = 0;

    struct address* dst = luaW_newaddress(L);
    dst->sa_family = dst->in4.sin_family = AF_INET;
    memcpy(&dst->in4.sin_addr, &ip_hdr->ip_dst, 4);
    dst->in4.sin_port = 0;

    lua_pushlstring(L, (const void*)&ip_hdr->ip_id, sizeof(ip_hdr->ip_id));
    lua_pushlstring(L, (const void*)&ip_hdr->ip_off, sizeof(ip_hdr->ip_off));
    lua_pushlstring(L, m, l);
    lua_concat(L, 3);

    return 4;
}

static int _write(lua_State* L) {
    struct tun* t = luaW_checkptr(L, 1, MT);
    struct address* src = luaL_checkudata(L, 2, "address");
    struct address* dst = luaL_checkudata(L, 3, "address");
    size_t l;
    const void* m = luaL_checklstring(L, 4, &l);

    if (src->sa_family != AF_INET || dst->sa_family != AF_INET) {
        luaL_error(L, "address must be IP4");
    }

    if (l < 4) {
        luaL_error(L, "malformed raw packet");
    }

    size_t buf_sz = (
        IP4_HDRLEN +    // ip
        UDP_HDRLEN +     // udp
        l-4
    );

    void* buf = calloc(1, buf_sz);

    struct ip* ip_hdr = buf;
    ip_hdr->ip_v = 4;
    assert(IP4_HDRLEN%sizeof(uint32_t)==0);
    ip_hdr->ip_hl = IP4_HDRLEN/sizeof(uint32_t);
    ip_hdr->ip_len = htons(IP4_HDRLEN+UDP_HDRLEN+l-4);
    ip_hdr->ip_id = *(uint16_t*)(m+0);
    ip_hdr->ip_off = *(uint16_t*)(m+2);
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_UDP;
    memcpy(&ip_hdr->ip_src, &src->in4.sin_addr, 4);
    memcpy(&ip_hdr->ip_dst, &dst->in4.sin_addr, 4);
    ip_hdr->ip_sum = checksum_ip(ip_hdr, IP4_HDRLEN);

    struct udphdr* udp_hdr = buf+IP4_HDRLEN;
    udp_hdr->uh_sport = src->in4.sin_port;
    udp_hdr->uh_dport = dst->in4.sin_port;
    udp_hdr->uh_ulen = htons(UDP_HDRLEN+l-4);

    memcpy(buf+IP4_HDRLEN+UDP_HDRLEN, m+4, l-4);

    int w_ret = write(t->fd, buf, buf_sz);
    free(buf);

    if (w_ret < 0) {
        luaL_error(L, "write() error: %s", strerror(errno));
    }

    if ((size_t)w_ret != buf_sz) {
        luaL_error(L, "truncated write()");
    }

    return 0;
}

static int _info(lua_State* L) {
    struct tun* t = luaW_checkptr(L, 1, MT);
    lua_pushinteger(L, t->fd);
    lua_pushstring(L, t->interface);
    return 2;
}

LUAMOD_API int luaopen_tun(lua_State* L) {
    luaW_declptr(L, MT, delete_tun_pvoid);

    luaL_getmetatable(L, MT);
    lua_getfield(L, -1, "__index");
    lua_pushcfunction(L, _info);
    lua_setfield(L, -2, "info");
    lua_pushcfunction(L, _read);
    lua_setfield(L, -2, "read");
    lua_pushcfunction(L, _write);
    lua_setfield(L, -2, "write");
    lua_pop(L, 2);

    lua_pushcfunction(L, luaW_newtun);
    return 1;
}

