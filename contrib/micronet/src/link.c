#include "server.h"

static void _link_kernel(struct node* n, struct packet* p) {
    // XXX implement
    if (p->dir == UP) {
        sendto_id(n, n->up, p);

    } else { // p->dir == DOWN
        sendto_id(n, n->as.link.down, p);
    }
}

int _link(lua_State* L) {
    struct node* n = _init_node(L);
    node_id down = luaN_checkid(L, NODE_ARGS(1));

    n->kernel = _link_kernel;
    n->as.link.down = down;

    return 0;
}
