#include "server.h"

#define PORT_MAX 65535
#define ICMP_ID_MAX 65535
#define NAT_TIMEOUT 60

static void _nat_kernel(struct node* n, struct packet* p) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, n->as.nat.kernel_ref);

    lua_pushlightuserdata(L, p);
    luaL_setmetatable(L, PACKET_MT);

    if (docall(L, 1, 1) != LUA_OK) {
        fprintf(stderr, "kernel error: %s\n",
            lua_tostring(L, -1)
        );
    }

    int isnum;
    int id = lua_tointegerx(L, -1, &isnum);
    const char* name = lua_tostring(L, -1);
    lua_pop(L, 1);

    if (isnum) {
        packet_refresh_sum(p);
        sendto_id(n, id, p);
    } else {
        if (!name) name = "unknown reason";
        DROP(n, p, "%s", name);
    }
}

int _nat(lua_State* L) {
    struct node* n = _init_node(L);
    struct subnet* up_ip = luaL_checkudata(L, NODE_ARGS(1), "subnet");
    struct subnet* up_gw = luaL_checkudata(L, NODE_ARGS(2), "subnet");
    luaL_checktype(L, NODE_ARGS(3), LUA_TFUNCTION);

    n->kernel = _nat_kernel;
    n->as.nat.ip = *up_ip;
    n->as.nat.gw = *up_gw;

    lua_pushvalue(L, NODE_ARGS(3));
    n->as.nat.kernel_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

