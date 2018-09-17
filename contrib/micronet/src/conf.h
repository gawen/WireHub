#ifndef MICRONET_CONF_H
#define MICRONET_CONF_H

#include "common.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define PACKET_MT   "packet"

typedef uint32_t node_id;
#define NODEID_NULL    ((node_id)0)

extern lua_State* L;
extern unsigned int nodes_max;
extern struct node* nodes;

struct node;
struct packet;

typedef void(*node_kernel_cb)(struct node* n, struct packet* p);

struct subnet {
    struct in_addr addr;
    uint8_t cidr;
};

struct route {
    struct subnet subnet;
    node_id id;
};

struct node {
    node_id id;
    struct sockaddr_in addr;
    struct packet* pkts_heap,* pkts_tail;
    node_kernel_cb kernel;
    char* type;
    node_id up;

    union {
        struct {
            struct subnet ip, gw;
        } peer;

        struct {
            node_id down;
        } link;

        struct {
            int count;
            struct route* routes;
        } wan;

        struct {
            int kernel_ref;
            struct subnet ip, gw;
        } nat;
    } as;
};

int load_config(const char* confpath);

node_id luaN_checkid(lua_State* L, int idx);
node_id luaN_checkidornil(lua_State* L, int idx);

struct node* _init_node(lua_State* L);

static inline struct node* NODE(unsigned int i) {
    assert(i > 0 && i <= nodes_max);
    return &nodes[i-1];
}

int docall (lua_State *L, int narg, int nres);

#endif  // MICRONET_CONF_H

