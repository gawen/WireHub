#include "luawh.h"
#include "net.h"

int luaW_version(lua_State *L) {
    lua_pushinteger(L, wh_version[0]);
    lua_pushinteger(L, wh_version[1]);
    lua_pushinteger(L, wh_version[2]);
    return 3;
}

static int _address_tostring(lua_State* L) {
    char s[64];
    struct address* a = luaL_checkudata(L, 1, "address");

    lua_pushstring(L, format_address(a, s, sizeof(s)));
    return 1;
}

static int _address_eq(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    struct address* b = luaL_checkudata(L, 2, "address");

    if (a->sa_family != b->sa_family) {
        lua_pushboolean(L, 0);
        return 1;
    }

    int cond;
    switch (a->sa_family) {
    case AF_INET:
        cond = memcmp(&a->in4.sin_addr, &b->in4.sin_addr, address_len(a) != 0 ||
            a->in4.sin_port != b->in4.sin_port) ? 1 : 0;
        break;

    case AF_INET6:
        cond = memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, address_len(a) != 0 ||
            a->in6.sin6_port != b->in6.sin6_port) ? 1 : 0;
        break;

    default:
        return luaL_error(L, "bad address");
    };

    lua_pushboolean(L, cond);
    return 1;
}

static int _address_lt(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    struct address* b = luaL_checkudata(L, 2, "address");

    if (a->sa_family < b->sa_family) {
        lua_pushboolean(L, 1);
        return 1;
    } else if (a->sa_family > b->sa_family) {
        lua_pushboolean(L, 0);
        return 1;
    }

    assert(a->sa_family == b->sa_family);

    int r;
    switch (a->sa_family) {
    case AF_INET:
        r = memcmp(&a->in4.sin_addr, &b->in4.sin_addr, address_len(a));
        break;

    case AF_INET6:
        r = memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, address_len(a));
        break;

    default:
        return luaL_error(L, "bad address");
    };

    if (r < 0) {
        lua_pushboolean(L, 1);
        return 1;
    } else if (r > 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    assert(r == 0);

    lua_pushboolean(L, address_port(a) < address_port(b) ? 1 : 0);
    return 1;
}

static int _address_addr(lua_State* L) {
    char s[64];

    struct address* a = luaL_checkudata(L, 1, "address");
    const size_t sl = sizeof(s);
    switch (a->sa_family) {
    case AF_INET:
        if (!inet_ntop(a->sa_family, &a->in4.sin_addr, s, sl-1)) {
            return 0;
        }
        break;

    case AF_INET6:
        if (!inet_ntop(a->sa_family, &a->in6.sin6_addr, s, sl-1)) {
            return 0;
        }
        break;
    default:
        return 0;
    };
    lua_pushstring(L, s);
    return 1;
}

static int _address_port(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    lua_pushinteger(L, address_port(a));
    return 1;
}

static int _address_same_subnet(lua_State* L) {
    const struct address* a = luaL_checkudata(L, 1, "address");
    const struct address* b = luaL_checkudata(L, 2, "address");
    int cidr = luaL_checkinteger(L, 3);

    if (a->sa_family != b->sa_family) {
        luaL_error(L, "address does not have the same type");
        return 0;
    }

    assert(address_len(a) == address_len(b));
    int max_cidr = address_len(a) * 8;

    if (cidr > max_cidr) {
        luaL_error(L, "bad CIDR");
        return 0;
    }

    const uint8_t* ap = NULL,* bp = NULL;

#define _GET_POINTER(ap, a) \
    switch ((a)->sa_family) { \
    case AF_INET:  ap = (const uint8_t*)&(a)->in4.sin_addr; break; \
    case AF_INET6: ap = (const uint8_t*)&(a)->in6.sin6_addr; break; \
    }

    _GET_POINTER(ap, a);
    _GET_POINTER(bp, b);

#undef _GET_POINTER

    assert(ap && bp);

    int is_same = 1;
    while (cidr > 0) {
        int c = cidr>8?8:cidr;
        uint8_t mask = ((1 << c)-1)<<(8-c);

        if ((*ap & mask) != (*bp & mask)) {
            is_same = 0;
            break;
        }

        ++ap, ++bp, cidr -= 8;
    }

    lua_pushboolean(L, is_same);
    return 1;
}

static inline uint32_t _subnet_mask(int cidr) {
    assert(0 <= cidr && cidr <= 32);
    if (cidr == 32) {
        return 0xffffffff;
    }

    return ((1 << cidr)-1) << (32-cidr);
}

static int _address_subnet_id(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");
    int cidr = luaL_checkinteger(L, 2);
    int idx = luaL_checkinteger(L, 3);

    if (a->sa_family != AF_INET) {
        luaL_error(L, "address must be IP4");
    }

    if (cidr < 0 || 32 < cidr) {
        luaL_error(L, "CIDR is between 0 and 32");
    }

    int64_t max_idx = (1L << (32-cidr)) - 2;
    if (idx < 1 || max_idx < idx) {
        return 0;
    }

    uint32_t mask = _subnet_mask(cidr);
    uint32_t addr = ntohl(a->in4.sin_addr.s_addr);
    addr &= mask;
    addr |= idx;

    struct address* n = luaW_newaddress(L);
    n->sa_family = n->in4.sin_family = AF_INET;
    n->in4.sin_addr.s_addr = htonl(addr);
    n->in4.sin_port = a->in4.sin_port;

    return 1;
}

static int _address_pack(lua_State* L) {
    struct address* a = luaL_checkudata(L, 1, "address");

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    switch (a->sa_family) {
    case AF_INET:
        luaL_addstring(&b, "\x04");
        luaL_addlstring(&b, (const void*)&a->in4.sin_addr, sizeof(a->in4.sin_addr));
        luaL_addlstring(&b, (const void*)&a->in4.sin_port, sizeof(a->in4.sin_port));
        break;

    case AF_INET6:
        luaL_addstring(&b, "\x06");
        luaL_addlstring(&b, (const void*)&a->in6.sin6_addr, sizeof(a->in6.sin6_addr));
        luaL_addlstring(&b, (const void*)&a->in6.sin6_port, sizeof(a->in6.sin6_port));
        break;

    default:
        luaL_error(L, "bad address");
    };

    luaL_pushresult(&b);
    return 1;
}

struct address* luaW_newaddress(lua_State* L) {
    struct address* a = lua_newuserdata(L, sizeof(struct address));

    if (luaL_newmetatable(L, "address")) {
        lua_pushcfunction(L, _address_tostring);
        lua_setfield(L, -2, "__tostring");

        lua_pushcfunction(L, _address_eq);
        lua_setfield(L, -2, "__eq");

        lua_pushcfunction(L, _address_lt);
        lua_setfield(L, -2, "__lt");

        lua_newtable(L);

        lua_pushcfunction(L, _address_addr);
        lua_setfield(L, -2, "addr");

        lua_pushcfunction(L, _address_port);
        lua_setfield(L, -2, "port");

        lua_pushcfunction(L, _address_same_subnet);
        lua_setfield(L, -2, "same_subnet");

        lua_pushcfunction(L, _address_subnet_id);
        lua_setfield(L, -2, "subnet_id");

        lua_pushcfunction(L, _address_pack);
        lua_setfield(L, -2, "pack");

        lua_setfield(L, -2, "__index");

        // XXX extend address with methods (:addr(), :port(), :subnet())
    }
    lua_setmetatable(L, -2);

    return a;
}

static int _gc_fd(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "fds");
    for (lua_pushnil(L); lua_next(L, -2) != 0; lua_pop(L, 1)) {
        if (lua_type(L, -1) == LUA_TBOOLEAN && lua_toboolean(L, -1)) {
            int fd = lua_tointeger(L, -2);
            fprintf(stderr, "warning: fd %d was not closed.\n", fd);
            close(fd);
        }
    }

    return 0;
}

void luaW_pushfd(lua_State* L, int fd) {
    lua_getfield(L, LUA_REGISTRYINDEX, "fds");

    if (lua_type(L, -1) == LUA_TNIL) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_newtable(L);
        lua_pushcfunction(L, _gc_fd);
        lua_setfield(L, -2, "__gc");
        lua_setmetatable(L, -2);

        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "fds");
    }

    lua_pushinteger(L, fd);
    lua_pushboolean(L, 1);
    lua_settable(L, -3);
    lua_pop(L, 1);

    lua_pushinteger(L, fd);
}

int luaW_getfd(lua_State* L, int idx) {
    int isint;
    int fd = lua_tointegerx(L, idx, &isint);

    if (!isint) {
        luaL_error(L, "bad element #%d (integer expected, got %s)",
            idx, lua_typename(L, lua_type(L, idx))
        );
    }

    lua_getfield(L, LUA_REGISTRYINDEX, "fds");
    int found = 1;
    if (lua_type(L, -1) == LUA_TNIL) {
        found = 0;
    } else {
        lua_pushinteger(L, fd);
        lua_gettable(L, -2);

        found = lua_type(L, -1) == LUA_TBOOLEAN && lua_toboolean(L, -1);
        lua_pop(L, 2);
    }

    if (!found) {
        luaL_error(L, "fd %d is not owned", fd);
    }

    return fd;
}


