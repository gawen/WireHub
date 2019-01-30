#include "key.h"
#include "luawh.h"
#include "net.h"
#include "os.h"
#include "packet.h"
#include "pcap.h"
#include <dirent.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>

/*** HELPERS *****************************************************************/

static void _expanduser(lua_State* L) {
    luaL_loadstring(L,
        "return string.gsub(..., '~', function() return os.getenv('HOME') end)"
    );

    lua_insert(L, -2);
    lua_call(L, 1, 1);
}

/*** FILE DESCRIPTOR *********************************************************/

static int _close(lua_State* L) {
    int fd = luaW_getfd(L, 1);

    close(fd);

    lua_getfield(L, LUA_REGISTRYINDEX, "fds");
    lua_pushinteger(L, fd);
    lua_pushnil(L);
    lua_settable(L, -3);

    return 0;
}

/*** BASE 64 *****************************************************************/

static int luaW_checkb64variant(lua_State* L, int idx) {
    int variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;

    int t = lua_type(L, idx);
    if (t != -1 && t != LUA_TNIL) {
        const char* s = luaL_checkstring(L, idx);
        if (strcmp(s, "wh") == 0) {
            variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
        } else if (strcmp(s, "wg") == 0) {
            variant = sodium_base64_VARIANT_ORIGINAL;
        }
    }

    return variant;
}

static int _tob64(lua_State* L) {
    size_t l;
    const char* m = luaL_checklstring(L, 1, &l);
    int variant = luaW_checkb64variant(L, 2);

    size_t b64l = sodium_base64_ENCODED_LEN(l, variant);
    luaL_Buffer b;
    char* b64 = luaL_buffinitsize(L, &b, b64l);
    sodium_bin2base64(b64, b64l, (const void*)m, l, variant);

    luaL_pushresultsize(&b, strlen(b64));
    return 1;
}

static int _fromb64(lua_State* L) {
    size_t b64l;
    const char* b64 = luaL_checklstring(L, 1, &b64l);
    int variant = luaW_checkb64variant(L, 2);

    luaL_Buffer b;
    void* bin = luaL_buffinitsize(L, &b, b64l);

    size_t l = b64l;
    if (sodium_base642bin(bin, l, b64, b64l, NULL, &l, NULL, variant) != 0) {
        luaL_error(L, "invalid base64: len:%d", b64l);
    }

    luaL_pushresultsize(&b, l);
    return 1;
}

/*** TIME ********************************************************************/

static int _now(lua_State* L) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    lua_Number n = now.tv_sec + (double)now.tv_nsec / 1.0e9;
    lua_pushnumber(L, n);
    return 1;
}

static int _todate(lua_State* L) {
    lua_Number nf = luaL_checknumber(L, 1);
    time_t n = nf; // cast

    luaL_Buffer b;
    size_t sz = sizeof"1991-08-25T20:57:08Z";
    char* buf = luaL_buffinitsize(L, &b, sz);
    sz = strftime(buf, sz, "%FT%TZ", gmtime(&n));
    luaL_pushresultsize(&b, sz);
    return 1;
}

/*** CRYPTO ******************************************************************/

static int _randombytes(lua_State* L) {
    int sz = luaL_checkinteger(L, 1);
    if (sz < 0) {
        luaL_error(L, "arg #1 is not positive");
    }

    luaL_Buffer b;
    void* buf = luaL_buffinitsize(L, &b, sz);
    randombytes_buf(buf, sz);
    luaL_pushresultsize(&b, sz);

    return 1;
}

/*** KEYS & SECRET KEYS ******************************************************/

// genkey(str key, int workbit[, int num_threads])
static int _genkey(lua_State* L) {
    const char* key = luaL_checkstring(L, 1);
    int workbit = luaL_checkinteger(L, 2);

    int num_threads = 1;
    if (lua_gettop(L) == 3) {
        num_threads = luaL_checkinteger(L, 3);
    }

    if (num_threads == 0) {
        num_threads = sysconf(_SC_NPROCESSORS_ONLN)*2-1;
    }

    void* sign_sk = luaW_newsecret(L, crypto_sign_ed25519_SECRETKEYBYTES);
    if (genkey(sign_sk, key, workbit, num_threads) < 0) {
        luaL_error(L, "key generation failed");
    }

    uint8_t sign_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_pk(sign_pk, sign_sk);
    lua_pushlstring(L, (const void*)sign_pk, sizeof(sign_pk));

    void* sk = luaW_newsecret(L, crypto_scalarmult_curve25519_BYTES);
    crypto_sign_ed25519_sk_to_curve25519(sk, sign_sk);

    uint8_t pk[crypto_scalarmult_curve25519_BYTES];
    crypto_scalarmult_curve25519_base(pk, sk);
    lua_pushlstring(L, (const void*)pk, sizeof(pk));

    return 4;
}

static int _publickey(lua_State* L) {
    const void* sk;

    if (lua_type(L, 1) == LUA_TSTRING) {
        size_t sz;
        sk = lua_tolstring(L, 1, &sz);
        if (sz != crypto_scalarmult_curve25519_BYTES) {
            luaL_error(L, "bad length");
        }
    } else {
        sk = luaW_checksecret(L, 1, crypto_scalarmult_curve25519_BYTES);
    }

    uint8_t pk[crypto_scalarmult_curve25519_BYTES];
    crypto_scalarmult_curve25519_base(pk, sk);
    lua_pushlstring(L, (void*)pk, sizeof(pk));
    return 1;
}

static int _readsk(lua_State* L) {
    (void)luaL_checkstring(L, 1);

    if (lua_gettop(L) != 1) {
        luaL_error(L, "function only takes one argument");
    }

    _expanduser(L);

    const char* filepath = lua_tostring(L, 1);
    assert(filepath);

    FILE* fh = fopen(filepath, "rb");

    if (!fh && errno == ENOENT) {
        lua_pushnil(L);
        return 1;
    }

    else if (!fh) {
        luaL_error(L, "cannot open file '%s': %s", filepath, strerror(errno));
    }

    int success = 0;
    long l;
    char* secret_b64 = NULL;
    if (
        fseek(fh, 0, SEEK_END) >= 0 &&
        (l = ftell(fh)) >= crypto_scalarmult_curve25519_KEYBASE64BYTES &&
        fseek(fh, 0, SEEK_SET) >= 0
    ) {
        secret_b64 = sodium_malloc(l);
        success = fread(secret_b64, 1, l, fh) == (size_t)l;
    }

    fclose(fh);

    if (success) {
        void* secret = luaW_newsecret(L, crypto_scalarmult_curve25519_BYTES);

        size_t bin_l = crypto_scalarmult_curve25519_BYTES;
        const int variant = sodium_base64_VARIANT_ORIGINAL;
        const char* b64_end;
        success = sodium_base642bin(
            secret,
            crypto_scalarmult_curve25519_BYTES,
            secret_b64,
            l,
            NULL,
            &bin_l,
            &b64_end,
            variant
        ) == 0;

        success &= bin_l == crypto_scalarmult_curve25519_BYTES;

        if (!success) {
            luaW_freesecret(luaW_ownsecret(L, -1, crypto_scalarmult_curve25519_BYTES));
            lua_pop(L, 1);
        }
    }

    if (secret_b64) {
        sodium_free(secret_b64), secret_b64 = NULL;
    }

    if (!success) {
        luaL_error(L, "cannot read file '%s': %s", filepath, strerror(errno));
    }

    return 1;
}

static int _burnsk(lua_State* L) {
    void* sk = luaW_ownsecret(L, 1, crypto_scalarmult_curve25519_BYTES);
    luaW_freesecret(sk);

    return 0;
}

static int _revealsk(lua_State* L) {
    void* sk = luaW_ownsecret(L, 1, crypto_scalarmult_curve25519_BYTES);
    lua_pushlstring(L, sk, crypto_scalarmult_curve25519_BYTES);
    luaW_freesecret(sk);

    return 1;
}

static int _workbit(lua_State* L) {
    size_t l;
    const void* pk = luaL_checklstring(L, 1, &l);
    if (l != crypto_sign_ed25519_PUBLICKEYBYTES) {
        luaL_error(L, "bad public key");
    }

    const void* k = luaL_checklstring(L, 2, &l);
    lua_pushinteger(L, workbit(pk, k, l));
    return 1;
}

static int _bid(lua_State* L) {
    size_t sz1, sz2;
    const char* s1 = luaL_checklstring(L, 1, &sz1);
    const char* s2 = NULL;

    if (lua_gettop(L) == 2) {
        s2 = luaL_checklstring(L, 2, &sz2);
    }

    if (s2 && sz1 != sz2) {
        luaL_error(L, "not same length.");
    }

#define sz sz1
    assert(sz % sizeof(uint32_t) == 0);
    unsigned int i;
    unsigned int r = 0;
    for(i=0; i<sz/sizeof(uint32_t); ++i) {
        uint32_t c = s2 ? *((uint32_t*)s1+i) ^ *((uint32_t*)s2+i) : *((uint32_t*)s1+i);

        int t0 = c == 0 ? 32 : __builtin_clz(be32toh(c)); // XXX why endianess?
        r += t0;
        if (t0 < 32) {
            break;
        }
    }

    if (r == sz*8) {
        --r;
    }
#undef sz

    lua_pushinteger(L, r+1);
    return 1;
}

static int _xor(lua_State* L) {
    size_t sz1, sz2;
    const char* a = luaL_checklstring(L, 1, &sz1);
    const char* b = luaL_checklstring(L, 2, &sz2);

    if (sz1 != sz2) {
        luaL_error(L, "not same length.");
    }

#define sz sz1
    luaL_Buffer buf;
    char* c = luaL_buffinitsize(L, &buf, sz);
    for (size_t i=0; i<sz; ++i) {
        c[i] = a[i] ^ b[i];
    }

    luaL_pushresultsize(&buf, sz);
#undef sz
    return 1;
}

/*** ADDRESS *****************************************************************/

static int _address(lua_State* L) {
    if (lua_type(L, 1) == LUA_TSTRING) {
        uint16_t port = 0;
        if (lua_gettop(L) >= 2 && lua_type(L, 2) != LUA_TNIL) {
            port = luaW_checkport(L, 2);
        }

        const char* mode_s = lua_tostring(L, 3);
        int numeric = mode_s && strcmp(mode_s, "numeric") == 0 ? 1 : 0;

        struct address* a = luaW_newaddress(L);
        if (parse_address(a, lua_tostring(L, 1), port, numeric) == -1) {
            luaL_error(L, "bad address: %s", lua_tostring(L, 1));
        }

        return 1;
    }

    else {
        luaL_checkudata(L, 1, "sockaddr");
        lua_pushvalue(L, 1);
        return 1;
    }
}

static int _unpack_address(lua_State* L) {
    size_t l;
    const char* b = luaL_checklstring(L, 1, &l);

    struct address* a = luaW_newaddress(L);

    switch (b[0]) {
    case 0x04:
        if (l < 1+4+2) {
            luaL_error(L, "bad address");
        }
        l = 1+4+2;

        a->sa_family = a->in4.sin_family = AF_INET;
        memcpy(&a->in4.sin_addr, b+1, 4);
        memcpy(&a->in4.sin_port, b+1+4, 2);
        break;

    case 0x06:
        if (l < 1+16+2) {
            luaL_error(L, "bad address");
        }
        l = 1+16+2;

        a->sa_family = a->in6.sin6_family = AF_INET6;
        memcpy(&a->in6.sin6_addr, b+1, 16);
        memcpy(&a->in6.sin6_port, b+1+16, 2);
        break;

    default:
        luaL_error(L, "bad packed address: %d", (int)b[0]);
    };

    lua_pushinteger(L, l);
    return 2;
}

static int _orchid(lua_State* L) {
    size_t cid_sz;
    const char* cid = luaL_checklstring(L, 1, &cid_sz);

    size_t l;
    const char* m = luaL_checklstring(L, 2, &l);

    uint16_t port = luaW_checkport(L, 3);

    struct address* a = luaW_newaddress(L);
    orchid(a, cid, cid_sz, m, l, port);

    return 1;
}

static int _set_address_port(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    uint16_t port = luaW_checkport(L, 2);

    struct address* an = luaW_newaddress(L);

    memcpy(an, a, sizeof(struct address));

    switch (a->sa_family) {
    case AF_INET:  an->in4.sin_port = htons(port); break;
    case AF_INET6: an->in6.sin6_port = htons(port); break;
    };

    return 1;
}

/*** NETWORK INTERFACES ******************************************************/

static int _netdevs(lua_State* L) {
    pcap_if_t* devs;
    char err[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, err) == PCAP_ERROR) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, err);
        return 2;
    }

    lua_newtable(L);

    int n;
    pcap_if_t* ifi;
    for (n=1, ifi=devs; ifi; ifi=ifi->next) {
        lua_newtable(L);

        lua_pushstring(L, ifi->name);
        lua_setfield(L, -2, "name");

        lua_pushstring(L, ifi->description);
        lua_setfield(L, -2, "description");

        lua_newtable(L);
        pcap_addr_t* ai;
        int o;
        for (o=1, ai=ifi->addresses; ai; ai=ai->next) {
            lua_newtable(L);

#define PUSH_SOCKADDR(v) \
            if (v) { \
                struct address* a = luaW_newaddress(L); \
                if (address_from_sockaddr(a, v) == -1) { \
                    lua_pop(L, 2); \
                    continue; \
                } \
            } else { \
                lua_pushnil(L); \
            }

            PUSH_SOCKADDR(ai->addr);
            lua_setfield(L, -2, "addr");

            PUSH_SOCKADDR(ai->netmask);
            lua_setfield(L, -2, "netmask");

            PUSH_SOCKADDR(ai->broadaddr);
            lua_setfield(L, -2, "broadcast");

            PUSH_SOCKADDR(ai->dstaddr);
            lua_setfield(L, -2, "dest");

#undef PUSH_SOCKADDR

            lua_seti(L, -2, o++);
        }
        lua_setfield(L, -2, "addresses");

#define PUSH_FLAG(v, f) \
        lua_pushboolean(L, ((ifi->flags & (f)) == (f))); \
        lua_setfield(L, -2, v);

        PUSH_FLAG("loopback", PCAP_IF_LOOPBACK);
        PUSH_FLAG("up", PCAP_IF_UP);
        PUSH_FLAG("running", PCAP_IF_RUNNING);
        PUSH_FLAG("wireless", PCAP_IF_WIRELESS);
        //PUSH_FLAG("conn_status", PCAP_IF_CONNECTION_STATUS);
        //PUSH_FLAG("conn_status_unknown", PCAP_IF_CONNECTION_STATUS_UNKNOWN);
        //PUSH_FLAG("conn_status_connected", PCAP_IF_CONNECTION_STATUS_CONNECTED);
        //PUSH_FLAG("conn_status_disconnected", PCAP_IF_CONNECTION_STATUS_DISCONNECTED);
        //PUSH_FLAG("conn_status_not_applicable ", PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE);
#undef PUSH_FLAG

        lua_seti(L, -2, n++);
    }

    pcap_freealldevs(devs), devs = NULL;
    return 1;
}

/*** SOCKETS *****************************************************************/

static int _socket_udp(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    int s = socket_udp(a);
    if (s == -1) {
        luaL_error(L, "socket error: %s", strerror(errno));
    }
    luaW_pushfd(L, s);
    return 1;
}

static int _socket_raw_udp(lua_State* L) {
    const char* proto = luaL_checkstring(L, 1);

    int hdrincl = 0;
    sa_family_t sa_family;
    if (strcmp(proto, "ip4") == 0) {
        sa_family = AF_INET;
    } else if (strcmp(proto, "ip6") == 0) {
        sa_family = AF_INET6;
    } else if (strcmp(proto, "ip4_hdrincl") == 0) {
        sa_family = AF_INET;
        hdrincl = 1;
    } else {
        return luaL_error(L, "unknown protocol: %s", proto);
    }

    int s = socket_raw_udp(sa_family, hdrincl);
    if (s == -1) {
        luaL_error(L, "socket error: %s", strerror(errno));
    }

    luaW_pushfd(L, s);
    return 1;
}

static int _send(lua_State* L) {
    int flags = 0;
    size_t l;
    int fd = luaW_getfd(L, 1);
    const char* m = luaL_checklstring(L, 2, &l);
    if (lua_type(L, 3) == LUA_TNUMBER) {
        flags = luaL_checkinteger(L, 3);
    }

    int r = send(fd, m, l, flags);

    lua_pushinteger(L, r);
    return 1;
}

static int _sendto(lua_State* L) {
    int flags = 0;
    struct address* a = NULL;
    size_t l;
    int fd = luaW_getfd(L, 1);
    const char* m = luaL_checklstring(L, 2, &l);
    if (lua_type(L, 3) == LUA_TNUMBER) {
        flags = luaL_checkinteger(L, 3);
        a = luaL_checkudata(L, 4, "address");
    } else {
        a = luaL_checkudata(L, 3, "address");
    }

    int r = sendto(fd, m, l, flags, &a->in, address_len(a));

    lua_pushinteger(L, r);
    return 1;
}

static int _sendto_raw_udp(lua_State* L) {
    int fd4 = luaW_getfd(L, 1);
    int fd6 = luaW_getfd(L, 2);
    size_t l;
    const char* m = luaL_checklstring(L, 3, &l);
    uint16_t src_port = luaW_checkport(L, 4);
    struct address* dst_addr = luaL_checkudata(L, 5, "address");

    if (l >= 0x10000 - UDP_HDRLEN) {
        luaL_error(L, "packet too long");
    }

    // prepare packet
    void* pkt = malloc(UDP_HDRLEN+l);

#define UDPHDR  ((struct udphdr*)(pkt+0))
    UDPHDR->uh_sport = htons(src_port);
    UDPHDR->uh_dport = htons(address_port(dst_addr));
    UDPHDR->uh_ulen = htons(UDP_HDRLEN+l);
    UDPHDR->uh_sum = 0x0000;
#undef UDPHDR

    memcpy(pkt+UDP_HDRLEN, m, l);

    int fd;
    switch (dst_addr->sa_family) {
    case AF_INET:  fd = fd4; break;
    case AF_INET6: fd = fd6; break;
    default: return luaL_error(L, "bad address family");
    };

#if 0
    printf("sendto(fd=%d, #m=%d, #addr=%d)\n", fd, (int)(8+l), address_len(dst_addr));

    printf("    \t");
    for (int i=0; i<16; ++i) {
        printf("%.2x ", i);
    }
    for (int i=0; i<(int)(8+l); ++i) {
        if (i%16 == 0) {
            printf("\n%.4x\t", i);
        }

        printf("%.2x ", (int)((uint8_t*)pkt)[i]);
    }
    printf("\n");
#endif

    const int flags = 0;
    ssize_t r = sendto(fd, pkt, 8+l, flags, &dst_addr->in, address_len(dst_addr));

    free(pkt);

    if (r < 0) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else if ((size_t)r != 8+l) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "truncated send: %dB != %dB", r, 8+l);
        return 2;
    } else {
        lua_pushboolean(L, 1);
        return 1;
    }
}

static int _recv(lua_State* L) {
    int fd = luaW_getfd(L, 1);
    int l = luaL_checkinteger(L, 2);
    int flags = 0;
    if (lua_gettop(L) == 3) {
        flags = luaL_checkinteger(L, 3);
    }

    luaL_Buffer b;
    char* m = luaL_buffinitsize(L, &b, l);
    ssize_t r = recv(fd, m, l, flags);

    if (r < 0 && (
        errno == EAGAIN ||
        errno == ECONNRESET)) {
        return 0;
    }

    if (r < 0) {
        luaL_error(L, "recv() failed: %s (%d)", strerror(errno), errno);
    }

    luaL_pushresultsize(&b, r);
    return 1;
}

static int _recvfrom(lua_State* L) {
    int fd = luaW_getfd(L, 1);
    int l = luaL_checkinteger(L, 2);
    int flags = 0;
    if (lua_gettop(L) == 3) {
        flags = luaL_checkinteger(L, 3);
    }

    luaL_Buffer b;
    char* m = luaL_buffinitsize(L, &b, l);
    struct address* a = luaW_newaddress(L);
    socklen_t al = sizeof(a->in6);
    ssize_t r = recvfrom(fd, m, l, flags, &a->in, &al);

    if (r < 0 && errno == EAGAIN) {
        return 0;
    }

    if (r < 0) {
        luaL_error(L, "recvfrom() failed: %s", strerror(errno));
    }

    if (r >= 0) {
        switch (al) {
        case sizeof(struct sockaddr_in):  a->sa_family = AF_INET; break;
        case sizeof(struct sockaddr_in6): a->sa_family = AF_INET6; break;
        default: luaL_error(L, "bad address size: %d", al);
        };
    }

    luaL_pushresultsize(&b, r);
    lua_insert(L, -2);
    return 2;
}

static int _sendto_raw_wg(lua_State* L) {
    int fd4 = luaW_getfd(L, 1);
    size_t l;
    const uint8_t* m = (const uint8_t*)luaL_checklstring(L, 2, &l);
    struct address* src_addr = luaL_checkudata(L, 3, "address");
    uint16_t wg_port = luaW_checkport(L, 4);

    // fd4 should be opened with wh.socket_raw_udp("ip4_hdrincl")

    // src_addr must be IP4
    if (src_addr->sa_family != AF_INET) {
        luaL_error(L, "bad address");
        return 0;
    }

#if 0   // XXX
    // src_addr must be from 127.0.0.0/8
    if ((ntohl(src_addr->in4.sin_addr.s_addr) & 0xff000000) != 0x7f000000) {
        luaL_error(L, "address is not loopback");
        return 0;
    }
#endif

    // packet must be wireguard
    if (m[0] > 4 || m[1] != 0 || m[2] != 0 || m[3] != 0) {
        luaL_error(L, "not a wireguard packet.");
        return 0;
    }

    // 0x10000 - 0x08 (UDP) - 0x14 (IP)
    if (l >= 0x10000 - IP4_HDRLEN - UDP_HDRLEN) {
        luaL_error(L, "packet too long");
    }

    // prepare packet
    void* pkt = malloc(IP4_HDRLEN+UDP_HDRLEN+l);

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = htonl(0x7f000001);
    dst_addr.sin_port = htons(wg_port);

#define IPHDR   ((struct ip*)(pkt+0))
    memset(IPHDR, 0, sizeof(struct ip));
    IPHDR->ip_hl = IP4_HDRLEN/sizeof(uint32_t);
    IPHDR->ip_v = 4;
    IPHDR->ip_tos = 0;
    IPHDR->ip_len = htons(IP4_HDRLEN+UDP_HDRLEN);
    IPHDR->ip_id = 0;
    IPHDR->ip_off = 0;
    IPHDR->ip_ttl = 255;
    IPHDR->ip_p = IPPROTO_UDP;
    memcpy(&IPHDR->ip_src, &src_addr->in4.sin_addr, 4);
    memcpy(&IPHDR->ip_dst, &dst_addr.sin_addr, 4);
    IPHDR->ip_sum = 0;
    //IPHDR->ip_sum = checksum_ip(IPHDR, IP4_HDRLEN);
#undef IPHDR

#define UDPHDR  ((struct udphdr*)(pkt+IP4_HDRLEN))
    UDPHDR->uh_sport = htons(address_port(src_addr));
    UDPHDR->uh_dport = dst_addr.sin_port;
    UDPHDR->uh_ulen = htons(UDP_HDRLEN+l);
    UDPHDR->uh_sum = 0x0000;
#undef UDPHDR

    memcpy(pkt+IP4_HDRLEN+UDP_HDRLEN, m, l);

#if 0
    printf("sendto_raw_wg(fd=%d, #m=%d, #addr=%d)\n", fd, (int)(8+l), address_len(dst_addr));

    printf("    \t");
    for (int i=0; i<16; ++i) {
        printf("%.2x ", i);
    }
    for (int i=0; i<(int)(8+l); ++i) {
        if (i%16 == 0) {
            printf("\n%.4x\t", i);
        }

        printf("%.2x ", (int)((uint8_t*)pkt)[i]);
    }
    printf("\n");
#endif

    const int flags = 0;
    ssize_t r = sendto(fd4, pkt, IP4_HDRLEN+UDP_HDRLEN+l, flags, (struct sockaddr*)&dst_addr, sizeof(dst_addr));

    free(pkt);

    if (r < 0) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else if ((size_t)r != 0x1c+l) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "truncated send: %dB != %dB", r, 8+l);
        return 2;
    } else {
        lua_pushboolean(L, 1);
        return 1;
    }
}

/*** NON INTRUSIVE SOCKETS ***************************************************/

static int _sniff(lua_State* L) {
    const char* interface = luaL_checkstring(L, 1);
    const char* direction_s = luaL_checkstring(L, 2);
    const char* proto_s = luaL_checkstring(L, 3);
    const char* expr = lua_tostring(L, 4);

    pcap_direction_t direction;
    if (strcmp(direction_s, "in") == 0) {
        direction = PCAP_D_IN;
    } else if (strcmp(direction_s, "out") == 0) {
        direction = PCAP_D_OUT;
    } else if (strcmp(direction_s, "inout") == 0) {
        direction = PCAP_D_INOUT;
    } else {
        luaL_error(L, "bad direction");
        return 0;
    }

    enum sniff_proto proto;
    if (strcmp(proto_s, "wg") == 0) {
        proto = SNIFF_PROTO_WG;
    } else if (strcmp(proto_s, "wh") == 0) {
        proto = SNIFF_PROTO_WH;
    } else {
        luaL_error(L, "unknown proto");
        return 0;
    }

    pcap_t* h = sniff(interface, direction, proto, expr);

    if (!h) {
        luaL_error(L, "pcap init error");
    }

    luaW_pushptr(L, "pcap", h);
    return 1;
}

static int _get_pcap(lua_State* L) {
    pcap_t* h = luaW_checkptr(L, 1, "pcap");

    int fd = pcap_get_selectable_fd(h);
    if (fd == PCAP_ERROR) {
        luaL_error(L, "pcap_get_selectable() failed: %s", pcap_geterr(h));
    }

    luaW_pushfd(L, fd);

    struct timeval* tv = pcap_get_required_select_timeout(h);

    if (tv) {
        lua_Number timeout = tv->tv_sec + (lua_Number)tv->tv_usec / 1e6;
        lua_pushnumber(L, timeout);
    } else {
        lua_pushnil(L);
    }

    return 2;
}

static int _pcap_next_udp(lua_State* L) {
    pcap_t* h = luaW_checkptr(L, 1, "pcap");

    struct pcap_pkthdr* hdr = NULL;
    const u_char* data = NULL;
    int r = pcap_next_ex(h, &hdr, &data);

    if (r == PCAP_ERROR) {
        return luaL_error(L, "pcap_next_ex() failed: %s", pcap_geterr(h));
    }

    assert (hdr);

    if (!data) {
        return 0;
    }

    if (hdr->caplen != hdr->len) {
        return 0;
    }

    const size_t pcap_hdr_sz = 16;
    if (hdr->len < pcap_hdr_sz) {
        return 0;
    }

    uint16_t proto;
    memcpy(&proto, data+14, sizeof(proto));
    proto = ntohs(proto);

    if (proto != ETHERTYPE_IP) {
        return 0;
    }

    const void* m;
    const void* d = data + pcap_hdr_sz;
    size_t l = hdr->len - pcap_hdr_sz;
    struct address* src = luaW_newaddress(L);
    struct address* dst = luaW_newaddress(L);
    if (ip4_to_udp(d, &m, &l, src, dst) == -1) {
        printf("FAILED! ip4_to_udp()\n");
        return 0;
    }

    lua_pushlstring(L, m, l);
    return 3;
}

static int _close_pcap(lua_State* L) {
    pcap_close(luaW_ownptr(L, 1, "pcap"));
    return 0;
}

/*** I/O POLLING *************************************************************/

static int _select(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    luaL_checktype(L, 2, LUA_TTABLE);
    luaL_checktype(L, 3, LUA_TTABLE);

    struct timeval* pval = NULL;

    if (lua_gettop(L) == 4 && lua_type(L, 4) != LUA_TNIL) {
        lua_Number timeout = luaL_checknumber(L, 4);
        pval = alloca(sizeof(struct timeval));
        pval->tv_sec = (time_t)timeout;
        pval->tv_usec = (timeout-pval->tv_sec)*1000000;
    }

    fd_set fds[3];

    lua_Integer nfds = 0;

    for (int i=0; i<3; ++i) {
        FD_ZERO(&fds[i]);
        int l = luaL_len(L, i+1);
        for (lua_Integer j=1; j<=l; ++j) {
            lua_geti(L, i+1, j);
            int ok;
            lua_Integer s = lua_tointegerx(L, -1, &ok);
            if (!ok) {
                luaL_error(L, "bad file descriptor type (integer expected, got %s)",
                        lua_typename(L, lua_type(L, -1))
                );
            }
            lua_pop(L, 1);

            FD_SET(s, &fds[i]);

            if (s > nfds) {
                nfds = s;
            }
        }
    }

    if (select(nfds+1, &fds[0], &fds[1], &fds[2], pval) == -1) {
        luaL_error(L, "select(): %s", strerror(errno));
    }

    for (int i=0; i<3; ++i) {
        lua_newtable(L);

        int l = luaL_len(L, i+1);
        for (lua_Integer j=1; j<=l; ++j) {
            lua_geti(L, i+1, j);
            lua_Integer s = lua_tointegerx(L, -1, NULL);
            lua_pop(L, 1);

            if (FD_ISSET(s, &fds[i])) {
                lua_pushboolean(L, 1);
                lua_seti(L, -2, s);
            }
        }
    }

    return 3;
}

/*** PACKET NETWORK CRYPTO ***************************************************/

static int _packet(lua_State* L) {
    size_t l;
    void* src_wg_sk = luaW_checksecret(L, 1, crypto_scalarmult_curve25519_BYTES);

    uint8_t src_wg_pk[crypto_scalarmult_curve25519_BYTES];
    if (crypto_scalarmult_base(src_wg_pk, src_wg_sk)) {
        luaL_error(L, "bad private key");
    }

    const void* dst_wg_pk = luaL_checklstring(L, 2, &l);
    if (l != crypto_sign_ed25519_PUBLICKEYBYTES) {
        luaL_error(L, "bad public key");
    }

    luaL_checktype(L, 3, LUA_TBOOLEAN);
    uint64_t is_nated = lua_toboolean(L, 3) ? 1 : 0;

    const void* m = luaL_checklstring(L, 4, &l);
    uint64_t flags_time_b = 0;
    flags_time_b |= (htobe64(now_seconds()) & packet_flags_TIMEMASK) << packet_flags_TIMESHIFT;
    flags_time_b |= (is_nated & packet_flags_DIRECTMASK) << packet_flags_DIRECTSHIFT;

    size_t sz = packet_size(l);
    luaL_Buffer b;
    void* pkt = luaL_buffinitsize(L, &b, sz);

    memcpy(packet_hdr(pkt), wh_pkt_hdr, sizeof(wh_pkt_hdr));
    memcpy(packet_src(pkt), src_wg_pk, crypto_scalarmult_curve25519_BYTES);
    memcpy(packet_flags_time(pkt), &flags_time_b, sizeof(flags_time_b));
    memcpy(packet_body(pkt), m, l);

    if (auth_packet(pkt, l, src_wg_sk, dst_wg_pk)) {
        luaL_error(L, "auth failed");
    }

    luaL_pushresultsize(&b, sz);

    return 1;
}

static int _open_packet(lua_State* L) {
    void* dst_wg_sk = luaW_checksecret(L, 1, crypto_scalarmult_curve25519_BYTES);
    size_t sz;
    const void* pkt = luaL_checklstring(L, 2, &sz);

    if (verify_packet(pkt, sz, dst_wg_sk)) {
        return 0;
    }

    uint64_t flags_time_s;
    memcpy(&flags_time_s, packet_flags_time(pkt), sizeof(flags_time_s));
    uint64_t time_s = be64toh((flags_time_s >> packet_flags_TIMESHIFT) & packet_flags_TIMEMASK);
    uint64_t is_nated = (flags_time_s >> packet_flags_DIRECTSHIFT) & packet_flags_DIRECTMASK;

    lua_pushlstring(L, packet_src(pkt), crypto_scalarmult_curve25519_BYTES);
    lua_pushboolean(L, is_nated);
    lua_pushinteger(L, time_s);
    lua_pushlstring(L, packet_body(pkt), sz-packet_size(0));

    return 4;
}

/*** DAEMON ******************************************************************/

static int _syslog_print(lua_State* L) {
    int n = lua_gettop(L);  /* number of arguments */
    int i;
    lua_getglobal(L, "tostring");

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (i=1; i<=n; i++) {
        const char *s;
        size_t l;
        lua_pushvalue(L, -1);  /* function to be called */
        lua_pushvalue(L, i);   /* value to print */
        lua_call(L, 1, 1);
        s = lua_tolstring(L, -1, &l);  /* get result */
        if (s == NULL)
        return luaL_error(L, "'tostring' must return a string to 'print'");
        if (i>1) luaL_addstring(&b, "\t");
        luaL_addlstring(&b, s, l);
        lua_pop(L, 1);  /* pop result */
    }

    luaL_pushresult(&b);
    const char* l = lua_tostring(L, -1);
    syslog(LOG_NOTICE, l);

    return 0;
}

static int _daemon(lua_State* L) {
    pid_t pid = fork();

    if (pid < 0) {
        luaL_error(L, "fork() failed: %s", strerror(errno));
    }

    if (pid > 0) {
        exit(0);
    }

    if (setsid() < 0) {
        fprintf(stderr, "setsid() failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "second fork() failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(0);
    }

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    //chdir("/");

    /* Close all open file descriptors */
    for (int x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
    lua_pushstring(L, "DAEMON");
    lua_pushboolean(L, 1);
    lua_rawset(L, -3);

    /* Open the log file */
    openlog ("wirehub", LOG_PID, LOG_DAEMON);

    lua_pushstring(L, "_print");
    lua_pushcfunction(L, _syslog_print);
    lua_rawset(L, -3);

    return 0;
}

/*** LOGGING *****************************************************************/

static int _color_mode(lua_State* L) {
	(void)L;

    static int mode = -1;
	const char *var;

    lua_getglobal(L, "DAEMON");
    int is_daemon = lua_type(L, -1) == LUA_TBOOLEAN && lua_toboolean(L, -1);
    lua_pop(L, 1);

    if (is_daemon) {
        mode = 0;
    }

    else {
        var = getenv("WH_COLOR_MODE");

        if (var && !strcmp(var, "always")) {
            mode = 1;
        } else if (var && !strcmp(var, "never")) {
            mode = 0;
        } else {
            mode = isatty(1) ? 1 : 0;
        }
    }

    assert(mode != -1);
    lua_pushboolean(L, mode);
	return 1;
}

static const luaL_Reg funcs[] = {
    {"address", _address},
    {"bid", _bid},
    {"burnsk", _burnsk},
    {"close", _close},
    {"close_pcap", _close_pcap},
    {"color_mode", _color_mode},
    {"daemon", _daemon},
    {"fromb64", _fromb64},
    {"genkey", _genkey},
    {"get_pcap", _get_pcap},
    {"netdevs", _netdevs},
    {"now", _now},
    {"open_packet", _open_packet},
    {"orchid", _orchid},
    {"packet", _packet},
    {"pcap_next_udp", _pcap_next_udp},
    {"publickey", _publickey},
    {"randombytes", _randombytes},
    {"readsk", _readsk},
    {"recv", _recv},
    {"recvfrom", _recvfrom},
    {"revealsk", _revealsk},
    {"select", _select},
    {"send", _send},
    {"sendto", _sendto},
    {"sendto_raw_udp", _sendto_raw_udp},
    {"sendto_raw_wg", _sendto_raw_wg},
    {"set_address_port", _set_address_port},
    {"sniff", _sniff},
    {"socket_raw_udp", _socket_raw_udp},
    {"socket_udp", _socket_udp},
    {"tob64", _tob64},
    {"todate", _todate},
    {"unpack_address", _unpack_address},
    {"version", luaW_version},
    {"workbit", _workbit},
    {"xor", _xor},
    {NULL, NULL},
};

static void _pcap_close(void* ud) {
    fprintf(stderr, "warning: pcap handler %p not closed.\n", ud);
    pcap_close((pcap_t*)ud);
}

LUAMOD_API int luaopen_whcore(lua_State* L) {
    luaL_checkversion(L);

    // initialize sodium
    if (sodium_init() == -1) {
        luaL_error(L, "sodium init failed.");
    }

    luaL_newlib(L, funcs);

#define SUB_LUAOPEN(x)  \
    do { \
        assert(luaopen_##x(L) == 1); \
        lua_setfield(L, -2, #x); \
    } while(0)

    SUB_LUAOPEN(ipc);
    SUB_LUAOPEN(ipc_event);
    SUB_LUAOPEN(wg);
    SUB_LUAOPEN(worker);

#if WH_ENABLE_MINIUPNPC
    SUB_LUAOPEN(upnp);
#endif

#undef SUB_LUAOPEN

    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, "wh_fds");

    luaW_declptr(L, "secret", sodium_free);
    luaW_declptr(L, "pcap", _pcap_close);

    return 1;
}

