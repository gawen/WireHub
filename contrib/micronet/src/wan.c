#include "server.h"

#define PORT_MAX 65535

static void _wan_kernel(struct node* n, struct packet* p) {
    assert(p->dir == UP);

    int i;
    for (i=0; i<n->as.wan.count; ++i) {
        struct route* r = &n->as.wan.routes[i];

        if (p->hdr.ip_dst.s_addr == r->subnet.addr.s_addr) {
            p->dir = DOWN;
            sendto_id(n, r->id, p);
            return;
        }
    }

    char dst[INET_ADDRSTRLEN+1];
    assert(inet_ntop(AF_INET, &p->hdr.ip_dst, dst, sizeof(dst)-1));
    DROP(n, p, "unknown route %s", dst);
}

static struct route* luaN_checkroutes(lua_State* L, int idx, int* pcount) {
    luaL_checktype(L, idx, LUA_TTABLE);

    int i;
    *pcount = luaL_len(L, idx);
    struct route* r = calloc(*pcount, sizeof(struct route));

    int l = luaL_len(L, idx);
    for (i=0; i<l; ++i) {
        lua_rawgeti(L, -1, i+1);
        lua_rawgeti(L, -1, 1);
        struct subnet* subnet = luaL_checkudata(L, -1, "subnet");
        lua_rawgeti(L, -2, 2);
        node_id id = luaN_checkid(L, -1);
        lua_pop(L, 3);

        r[i].subnet = *subnet;
        r[i].id = id;
    }

    return r;
}

int _wan(lua_State* L) {
    struct node* n = _init_node(L);
    int count;
    struct route* r = luaN_checkroutes(L, NODE_ARGS(1), &count);

    n->kernel = _wan_kernel;
    n->as.wan.count = count;
    n->as.wan.routes = r;

    return 0;
}

