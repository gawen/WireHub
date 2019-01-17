#include "wireguard.h"
#include "luawh.h"
#include <sys/utsname.h>

int check_linux_version(void) {
    struct utsname name;
    uname(&name);

    char minver[] = WH_LINUX_MINVERSION;
    char* t = name.release;
    unsigned int i = 0;
    while (i<sizeof(minver)) {
        t = strtok(t, ".");
		int v = atoi(t);

        if (v > minver[i]) {
            return 1;
        } else if (v < minver[i]) {
            return 0;
        }

        t = NULL;
        ++i;
    }

    return 1;
}

int check_wireguard_module(void) {
    FILE* fh = fopen("/proc/modules", "r");

    int found = 0;
    char buf[256];
    while (fgets(buf, sizeof(buf), fh)) {
        char modname[64];
        sscanf(buf, "%s", modname);

        if (strcmp(modname, "wireguard") == 0) {
            found = 1;
            break;
        }
    }

    fclose(fh);

    return found;
}

static int _check(lua_State* L) {
    if (!check_linux_version()) {
        lua_pushstring(L, "oldkernel");
    }

    else if (!check_wireguard_module()) {
        lua_pushstring(L, "notloaded");
    }

    else {
        lua_pushstring(L, "ok");
    }

    return 1;
}

static void _push_allowedip(lua_State* L, struct wg_allowedip* allowedip) {
    lua_newtable(L);

    struct address* ip = luaW_newaddress(L);
    ip->sa_family = allowedip->family;
    switch (ip->sa_family) {
    case AF_INET:  memcpy(&ip->in4.sin_addr, &allowedip->ip4, sizeof(allowedip->ip4)); break;
    case AF_INET6: memcpy(&ip->in6.sin6_addr, &allowedip->ip6, sizeof(allowedip->ip6)); break;
    default: perror("unknown sa_family");
    };
    lua_rawseti(L, -2, 1);

    lua_pushinteger(L, allowedip->cidr);
    lua_rawseti(L, -2, 2);
}

static void _push_peer(lua_State* L, struct wg_peer* p) {
    lua_newtable(L);

    if (p->flags & WGPEER_HAS_PUBLIC_KEY) {
        lua_pushlstring(L, (const void*)p->public_key, 32);
        lua_setfield(L, -2, "public_key");
    }

    if (p->flags & WGPEER_HAS_PRESHARED_KEY) {
        memcpy(luaW_newsecret(L, 32), p->preshared_key, 32);
        lua_setfield(L, -2, "preshared_key");
    }

    struct address* endpoint = luaW_newaddress(L);
    endpoint->sa_family = p->endpoint.addr.sa_family;
    switch (endpoint->sa_family) {
    case AF_INET:  memcpy(&endpoint->in4, &p->endpoint.addr4, sizeof(endpoint->in4)); break;
    case AF_INET6: memcpy(&endpoint->in6, &p->endpoint.addr6, sizeof(endpoint->in6)); break;
    default: perror("unknown sa_family");
    };
    lua_setfield(L, -2, "endpoint");

    lua_pushnumber(L, p->last_handshake_time.tv_sec + (double)p->last_handshake_time.tv_nsec / 1.0e9);
    lua_setfield(L, -2, "last_handshake_time");

    lua_pushnumber(L, p->rx_bytes);
    lua_setfield(L, -2, "rx_bytes");

    lua_pushnumber(L, p->tx_bytes);
    lua_setfield(L, -2, "tx_bytes");

    lua_pushnumber(L, p->persistent_keepalive_interval);
    lua_setfield(L, -2, "persistent_keepalive_interval");

    lua_newtable(L);
    struct wg_allowedip* allowedip;
    wg_for_each_allowedip(p, allowedip) {
        _push_allowedip(L, allowedip);
        lua_rawseti(L, -2, luaL_len(L, -2)+1);
    }
    lua_setfield(L, -2, "allowedips");
}

static void _push_device(lua_State* L, struct wg_device* d) {
    lua_newtable(L);

    lua_pushstring(L, d->name);
    lua_setfield(L, -2, "name");

    lua_pushinteger(L, d->ifindex);
    lua_setfield(L, -2, "ifindex");

    if (d->flags & WGDEVICE_HAS_PUBLIC_KEY) {
        lua_pushlstring(L, (const void*)d->public_key, 32);
        lua_setfield(L, -2, "public_key");
    }

    if (d->flags & WGDEVICE_HAS_PRIVATE_KEY) {
        memcpy(luaW_newsecret(L, 32), d->private_key, 32);
        lua_setfield(L, -2, "private_key");
    }

    lua_pushinteger(L, d->fwmark);
    lua_setfield(L, -2, "fwmark");

    lua_pushinteger(L, d->listen_port);
    lua_setfield(L, -2, "listen_port");

    lua_newtable(L);
    struct wg_peer* p;
	wg_for_each_peer(d, p) {
        _push_peer(L, p);
        lua_rawseti(L, -2, luaL_len(L, -2)+1);
    }
    lua_setfield(L, -2, "peers");
}

#define IFK(x)  if (strcmp(k, x) == 0)

static void _check_allowedip(lua_State* L, int idx, struct wg_device* d, struct wg_peer* p) {
    assert(idx > 0);

    struct wg_allowedip* allowedip = calloc(1, sizeof(struct wg_allowedip));

    if (p->last_allowedip) {
        p->last_allowedip->next_allowedip = allowedip;
    } else {
        p->first_allowedip = allowedip;
    }
    p->last_allowedip = allowedip;

    lua_rawgeti(L, idx, 1);
    struct address* ip = luaL_testudata(L, -1, "address");
    if (!ip) {
        wg_free_device(d);
        luaL_error(L, "invalid allowedip's ip");
    }

    allowedip->family = ip->sa_family;
    int max_cidr;
    switch (ip->sa_family) {
    case AF_INET:
        memcpy(&allowedip->ip4, &ip->in4.sin_addr, sizeof(allowedip->ip4));
        max_cidr = 32;
        break;
    case AF_INET6:
        memcpy(&allowedip->ip6, &ip->in6.sin6_addr, sizeof(allowedip->ip6));
        max_cidr = 128;
        break;

    default:
        luaL_error(L, "unknown sa_family");
    };
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 2);
    int isnum;
    lua_Integer cidr = lua_tointegerx(L, -1, &isnum);
    if (!isnum || cidr < 0 || max_cidr < cidr) {
        wg_free_device(d);
        luaL_error(L, "invalid CIDR");
    }
    allowedip->cidr = cidr;
    lua_pop(L, 1);
}

static void _check_peer(lua_State* L, int idx, struct wg_device* d) {
    assert(idx > 0);

    struct wg_peer* p = calloc(1, sizeof(struct wg_peer));

    if (d->last_peer) {
        d->last_peer->next_peer = p;
    } else {
        d->first_peer = p;
    }
    d->last_peer = p;

    for (lua_pushnil(L); lua_next(L, idx) != 0; lua_pop(L, 1)) {
        const char* k = lua_tostring(L, -2);

        IFK("remove_me") {
            if (lua_toboolean(L, -1)) {
                p->flags |= WGPEER_REMOVE_ME;
            }
        }

        else IFK("replace_allowedips") {
            if (lua_toboolean(L, -1)) {
                p->flags |= WGPEER_REPLACE_ALLOWEDIPS;
            }
        }

        else IFK("public_key") {
            size_t sz;
            const char* k = lua_tolstring(L, -1, &sz);

            if (sz != 32) {
                wg_free_device(d);
                luaL_error(L, "invalid public key");
            }

            memcpy(p->public_key, k, 32);
            p->flags |= WGPEER_HAS_PUBLIC_KEY;
        }

        else IFK("preshared_key") {
            const void* preshared_key = luaW_tosecret(L, -1, 32);
            if (!preshared_key) {
                wg_free_device(d);
                luaL_error(L, "invalid preshared key");
            }

            memcpy(p->preshared_key, preshared_key, 32);
            p->flags |= WGPEER_HAS_PRESHARED_KEY;
        }

        else IFK("endpoint") {
            struct address* endpoint = luaL_testudata(L, -1, "address");

            if (!endpoint) {
                wg_free_device(d);
                luaL_error(L, "invalid endpoint");
            }

            p->endpoint.addr.sa_family = endpoint->sa_family;
            switch (endpoint->sa_family) {
            case AF_INET:  memcpy(&p->endpoint.addr4, &endpoint->in4, sizeof(endpoint->in4)); break;
            case AF_INET6: memcpy(&p->endpoint.addr6, &endpoint->in6, sizeof(endpoint->in6)); break;
            default: perror("unknown sa_family");
            };
        }

        else IFK("persistent_keepalive_interval") {
            int isnum;
            lua_Integer v = lua_tointegerx(L, -1, &isnum);

            if (!isnum || v < 0) {
                luaL_error(L, "invalid persistent_keepalive_interval");
            }

            p->persistent_keepalive_interval = v;
            p->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
        }

        else IFK("allowedips") {
            for (lua_Integer i = 1; i <= luaL_len(L, -1); ++i) {
                lua_rawgeti(L, -1, i);
                 _check_allowedip(L, lua_gettop(L), d, p);
                lua_pop(L, 1);
            }
        }
    }
}

static struct wg_device* _check_device(lua_State* L, int idx) {
    assert(idx > 0);

    luaL_checktype(L, idx, LUA_TTABLE);

    struct wg_device* d = calloc(1, sizeof(struct wg_device));
    for (lua_pushnil(L); lua_next(L, idx) != 0; lua_pop(L, 1)) {
        const char* k = lua_tostring(L, -2);

        IFK("name") {
            size_t sz;
            const char* name = lua_tolstring(L, -1, &sz);

            if (sz > IFNAMSIZ) {
                wg_free_device(d);
                luaL_error(L, "device's name too long");
            }

            memcpy(d->name, name, sz);
        }

        else IFK("ifindex") {
            int isnum;
            int ifindex = lua_tointegerx(L, -1, &isnum);

            if (!isnum || ifindex < 0 || UINT32_MAX < (unsigned int)ifindex) {
                wg_free_device(d);
                luaL_error(L, "invalid ifindex");
            }

            d->ifindex = ifindex;
        }

        else IFK("replace_peers") {
            if (lua_toboolean(L, -1)) {
                d->flags |= WGDEVICE_REPLACE_PEERS;
            }
        }

        else IFK("public_key") {
            size_t sz;
            const char* k = lua_tolstring(L, -1, &sz);

            if (sz != 32) {
                wg_free_device(d);
                luaL_error(L, "invalid public key");
            }

            memcpy(d->public_key, k, 32);
            d->flags |= WGDEVICE_HAS_PUBLIC_KEY;
        }

        else IFK("private_key") {
            const void* sk = luaW_tosecret(L, -1, 32);
            if (!sk) {
                wg_free_device(d);
                luaL_error(L, "invalid private key");
            }
            memcpy(d->private_key, sk, 32);
            d->flags |= WGDEVICE_HAS_PRIVATE_KEY;
        }

        else IFK("fwmark") {
            int isnum;
            int fwmark = lua_tointegerx(L, -1, &isnum);

            if (!isnum || fwmark < 0 || UINT16_MAX < (unsigned int)fwmark) {
                wg_free_device(d);
                luaL_error(L, "invalid fwmark");
            }

            d->fwmark = fwmark;
            d->flags |= WGDEVICE_HAS_FWMARK;
        }

        else IFK("listen_port") {
            int isnum;
            int listen_port = lua_tointegerx(L, -1, &isnum);

            if (!isnum || listen_port < 0 || UINT16_MAX < (unsigned int)listen_port) {
                wg_free_device(d);
                luaL_error(L, "invalid listen_port");
            }

            d->listen_port = listen_port;
            d->flags |= WGDEVICE_HAS_LISTEN_PORT;
        }

        else IFK("peers") {
            for (lua_Integer i = 1; i <= luaL_len(L, -1); ++i) {
                lua_rawgeti(L, -1, i);
                 _check_peer(L, lua_gettop(L), d);
                lua_pop(L, 1);
            }
        }

    }

    return d;
}

#undef IFK

static int _list_device_names(lua_State* L) {
    char* device_names = wg_list_device_names();
    if (!device_names) {
        return luaL_error(L, "wg_list_device_names() failed");
    }

    lua_newtable(L);
    char* device_name;
    size_t len;
    wg_for_each_device_name(device_names, device_name, len) {
        lua_pushlstring(L, device_name, len);
        lua_rawseti(L, -2, luaL_len(L, -2) + 1);
    }

    free(device_names);

    return 1;
}

static int _add_device(lua_State* L) {
    const char* device_name = luaL_checkstring(L, 1);
    int ret = wg_add_device(device_name);
    if (ret < 0) {
        return luaL_error(L, "wg_add_device() failed: %s", strerror(-ret));
    }

    return 0;
}

static int _del_device(lua_State* L) {
    const char* device_name = luaL_checkstring(L, 1);
    int ret = wg_del_device(device_name);
    if (ret < 0) {
        return luaL_error(L, "wg_del_device() failed: %s", strerror(-ret));
    }

    return 0;
}

static int _get_device(lua_State* L) {
    const char* device_name = luaL_checkstring(L, 1);
    struct wg_device* device;
    int ret = wg_get_device(&device, device_name);
    if (ret < 0) {
        if (ret == -ENODEV) {
            return 0;
        }

        return luaL_error(L, "wg_get_device() failed: %s", strerror(-ret));
    }

    _push_device(L, device);
    wg_free_device(device), device = NULL;

    return 1;
}

static int _set_device(lua_State* L) {
    struct wg_device* device = _check_device(L, 1);
    int ret = wg_set_device(device);
    wg_free_device(device), device = NULL;

    if (ret < 0) {
        return luaL_error(L, "wg_set_device() failed: %s", strerror(-ret));
    }

    return 0;
}

// XXX use libmnl
// XXX injection!

#define CMD(...)    do { \
    char cmd[256]; \
    snprintf(cmd, sizeof(cmd), __VA_ARGS__); \
    int ret = system(cmd); \
    if (ret < 0) { \
        luaL_error(L, "command returned %d: %s", ret, cmd); \
    } \
} while(0)

static int _set_link(lua_State* L) {
    const char* ifn = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TBOOLEAN);
    int up = lua_toboolean(L, 2);

    // XXX check ifn is wireguard

    CMD("ip link set %s %s", ifn, up ? "up" : "down");

    return 0;
}

static int _set_addr(lua_State* L) {
    const char* ifn = luaL_checkstring(L, 1);

    // XXX check ifn is wireguard

    CMD("ip addr flush %s", ifn);

    // if only argument is interface, flush addresses
    if (lua_gettop(L) == 1) {
        return 0;
    }

    // else, add address
    struct address* addr = luaL_testudata(L, 2, "address");
    char addr_s[INET_ADDRSTRLEN+1];
    int max_cidr;
    switch (addr->sa_family) {
    case AF_INET:
        max_cidr = 32;
        inet_ntop(addr->sa_family, &addr->in4.sin_addr, addr_s, sizeof(addr_s)-1);
        break;
    case AF_INET6:
        max_cidr = 128;
        inet_ntop(addr->sa_family, &addr->in6.sin6_addr, addr_s, sizeof(addr_s)-1);
        break;

    default:
        luaL_error(L, "unknown sa_family");
    };

    int isnum;
    int cidr = lua_tointegerx(L, 3, &isnum);
    if (!isnum || cidr < 0 || max_cidr < cidr) {
        return luaL_error(L, "invalid CIDR");
    }

    CMD("ip addr add %s/%d dev %s", addr_s, cidr, ifn);

    return 0;
}

#undef CMD

static const luaL_Reg funcs[] = {
    {"add", _add_device},
    {"check", _check},
    {"delete", _del_device},
    {"get", _get_device},
    {"list_names", _list_device_names},
    {"set", _set_device},
    {"set_addr", _set_addr},
    {"set_link", _set_link},
    { NULL, NULL }
};

LUAMOD_API int luaopen_wg(lua_State* L) {
    luaL_checkversion(L);
    luaL_newlib(L, funcs);

    {
        char minversion[] = WH_LINUX_MINVERSION;
        unsigned int i;

        lua_newtable(L);
        for (i=0; i<sizeof(minversion); ++i) {
            lua_pushinteger(L, minversion[i]);
            lua_rawseti(L, -2, i+1);
        }

        lua_setfield(L, -2, "LINUX_MINVER");
    }
    return 1;
}

