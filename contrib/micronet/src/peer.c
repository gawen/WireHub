#include "server.h"

static void _peer_kernel(struct node* n, struct packet* p) {
    if (p->dir == UP) {
        if (n->as.peer.ip.addr.s_addr != p->hdr.ip_src.s_addr) {
            DROP(n, p, "bad source address");
        }

        sendto_id(n, n->up, p);
    }

    else {  // p->dir == DOWN
        if (n->as.peer.ip.addr.s_addr != p->hdr.ip_dst.s_addr) {
            DROP(n, p, "bad destination address");
        }

        if (n->addr.sin_addr.s_addr == 0) {
            DROP(n, p, "unknown micronet client address");
        }

        struct iovec iov[1];
        iov[0].iov_base = p->body;
        iov[0].iov_len = p->sz;
        _udp_sendto(&n->addr, iov, 1);

        LOG("\n");
        free(p), p=NULL;
    }
}

int _peer(lua_State* L) {
    struct node* n = _init_node(L);
    struct subnet* up_ip = luaL_checkudata(L, NODE_ARGS(1), "subnet");
    struct subnet* up_gw = luaL_checkudata(L, NODE_ARGS(2), "subnet");

    n->kernel = _peer_kernel;
    n->as.peer.ip = *up_ip;
    n->as.peer.gw = *up_gw;


    return 0;
}


