#include "server.h"
#include "conf.h"

extern char _luacode_server[];
extern unsigned int _luacode_server_sz;

lua_State* L = NULL;

unsigned int nodes_max = 0;
struct node* nodes = NULL;

node_id luaN_checkid(lua_State* L, int idx) {
    lua_Integer i = luaL_checkinteger(L, idx);
    if (i < 1 || nodes_max < i) { luaL_error(L, "invalid ID"); }
    return i;
}

node_id luaN_checkidornil(lua_State* L, int idx) {
    lua_Integer i = luaL_checkinteger(L, idx);
    if (i < 0 || nodes_max < i) { luaL_error(L, "invalid ID"); }
    return i;
}

static inline uint32_t _subnet_netmask(int cidr) {
    assert(0 <= cidr && cidr <= 32);
    if (cidr == 32) {
        return 0xffffffff;
    }

    return ((1 << cidr)-1) << (32-cidr);
}

/*
** Message handler used to run all chunks
*/
static int msghandler (lua_State *L) {
  const char *msg = lua_tostring(L, 1);
  if (msg == NULL) {  /* is error object not a string? */
    if (luaL_callmeta(L, 1, "__tostring") &&  /* does it have a metamethod */
        lua_type(L, -1) == LUA_TSTRING)  /* that produces a string? */
      return 1;  /* that is the message */
    else
      msg = lua_pushfstring(L, "(error object is a %s value)",
                               luaL_typename(L, 1));
  }
  luaL_traceback(L, L, msg, 1);  /* append a standard traceback */
  return 1;  /* return the traceback */
}


/*
** Interface to 'lua_pcall', which sets appropriate message function
** and C-signal handler. Used to run all chunks.
*/
int docall (lua_State *L, int narg, int nres) {
  int status;
  int base = lua_gettop(L) - narg;  /* function index */
  lua_pushcfunction(L, msghandler);  /* push message handler */
  lua_insert(L, base);  /* put it under function and args */
  status = lua_pcall(L, narg, nres, base);
  lua_remove(L, base);  /* remove message handler from the stack */
  return status;
}

static int _addr_tostring(lua_State* L) {
    struct in_addr* addr = luaL_checkudata(L, 1, "ip4");

    char addr_s[INET_ADDRSTRLEN+1];
    inet_ntop(AF_INET, addr, addr_s, sizeof(addr_s)-1);

    lua_pushstring(L, addr_s);
    return 1;
}

static int _addr_index(lua_State* L) {
    struct in_addr* addr = luaL_checkudata(L, 1, "ip4");
    const char* name = luaL_checkstring(L, 2);
    int is_get = lua_gettop(L) == 2;

    if (strcmp(name, "s_addr") == 0) {
        if (is_get) {
            lua_pushnumber(L, ntohl(addr->s_addr));
            return 1;
        } else {
            addr->s_addr = htonl(luaL_checkinteger(L, 3));
        }
    }

    return 0;
    //return luaL_error(L, "unknown field: %s", name);
}

static int _now(lua_State* L) {
    lua_Number n = now.tv_sec + (double)now.tv_nsec / 1.0e9;
    lua_pushnumber(L, n);
    return 1;
}

static void _pushsubnetmt(lua_State* L);

static int _subnet_ip(lua_State* L) {
    struct subnet* subnet = luaL_checkudata(L, 1, "subnet");

    struct in_addr* addr = lua_newuserdata(L, sizeof(struct in_addr));
    *addr = subnet->addr;
    if (luaL_newmetatable(L, "ip4")) {
        lua_pushcfunction(L, _addr_index);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, _addr_index);
        lua_setfield(L, -2, "__newindex");
        lua_pushcfunction(L, _addr_tostring);
        lua_setfield(L, -2, "__tostring");
    }
    lua_setmetatable(L, -2);
    return 1;
}

static int _subnet_next(lua_State* L) {
    struct subnet* subnet = luaL_checkudata(L, 1, "subnet");
    struct subnet* next = lua_newuserdata(L, sizeof(struct subnet));

    _pushsubnetmt(L);
    lua_setmetatable(L, -2);

    next->cidr = subnet->cidr;

    uint32_t netmask = _subnet_netmask(subnet->cidr);
    uint32_t ip = ntohl(subnet->addr.s_addr);
    uint32_t subnet_ip = ip & ~netmask;
    ++subnet_ip;
    if ((subnet_ip & netmask) != 0) {
        luaL_error(L, "out of IPs");
    }
    ip = (ip & netmask) | subnet_ip;

    next->addr.s_addr = htonl(ip);
    return 1;
}

static int _subnet_tostring(lua_State* L) {
    struct subnet* subnet = luaL_checkudata(L, 1, "subnet");

    char addr_s[INET_ADDRSTRLEN+1];
    inet_ntop(AF_INET, &subnet->addr, addr_s, sizeof(addr_s)-1);

    lua_pushfstring(L, "%s/%d", addr_s, subnet->cidr);
    return 1;
}

static void _pushsubnetmt(lua_State* L) {
    if (luaL_newmetatable(L, "subnet")) {
        lua_newtable(L); // "__index"

        lua_pushcfunction(L, _subnet_ip);
        lua_setfield(L, -2, "ip");
        lua_pushcfunction(L, _subnet_next);
        lua_setfield(L, -2, "next");

        lua_pushcfunction(L, _subnet_tostring);
        lua_setfield(L, -2, "__tostring");

        lua_setfield(L, -2, "__index");
    }
}

static int _subnet(lua_State* L) {
    const char* addr_s = luaL_checkstring(L, 1);
    lua_Integer cidr = luaL_checkinteger(L, 2);

    if (cidr < 0 || 32 < cidr) {
        luaL_error(L, "bad CIDR");
    }

    struct subnet* subnet = lua_newuserdata(L, sizeof(struct subnet));

    int ret = inet_pton(AF_INET, addr_s, &subnet->addr);
    if (ret <= 0) {
        luaL_error(L, "bad IPv4");
    }
    subnet->cidr = cidr;

    _pushsubnetmt(L);
    lua_setmetatable(L, -2);

    return 1;
}

static int _randomwan(lua_State* L) {
    struct subnet* subnet = lua_newuserdata(L, sizeof(struct subnet));

    int fd = open("/dev/urandom", 0);
    if (read(fd, &subnet->addr, 4) < 4) {
        luaL_error(L, "urandom failed");
    }
    subnet->cidr = 0;

    _pushsubnetmt(L);
    lua_setmetatable(L, -2);

    return 1;
}

static int _alloc_nodes(lua_State* L) {
    if (nodes) {
        luaL_error(L, "already allocated");
    }

    lua_Integer max = luaL_checkinteger(L, 1);

    if (max < 0) {
        luaL_error(L, "max cannot be negative");
    }

    nodes_max = max;
    nodes = calloc(max, sizeof(struct node));

    return 0;
}

struct node* _init_node(lua_State* L) {
    node_id i = luaN_checkid(L, 1);
    const char* type = lua_tostring(L, 2);
    node_id up = luaN_checkidornil(L, 3);

    struct node* n = NODE(i);
    n->id = i;
    n->type = type ? strdup(type) : NULL;
    n->up = up;

    return n;
}

static int packet_tostring(lua_State* L) {
    struct packet* p = luaL_checkudata(L, 1, PACKET_MT);

    char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];
    assert(inet_ntop(AF_INET, &p->hdr.ip_src, src, sizeof(src)-1));
    assert(inet_ntop(AF_INET, &p->hdr.ip_dst, dst, sizeof(dst)-1));

    const char* type;
    switch (p->hdr.ip_p) {
    case IPPROTO_TCP:  type = "TCP"; break;
    case IPPROTO_UDP:  type = "UCP"; break;
    case IPPROTO_ICMP: type = "ICMP"; break;
    default:           type = "?"; break;
    };

    lua_pushfstring(L, "packet p:%s dir:%s ",
        type,
        p->dir == UP ? "UP" : "DOWN",
        src, dst,
        p
    );

    const void* payload = packet_ip_payload(p, NULL);

    switch (p->hdr.ip_p) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        {
            uint16_t sport = ntohs(((const uint16_t*)payload)[0]);
            uint16_t dport = ntohs(((const uint16_t*)payload)[1]);
            lua_pushfstring(L, "src:%s:%d dst:%s:%d", src, sport, dst, dport);
        }
        break;
    default:
        lua_pushfstring(L, "src:%s dst:%s", src, dst);
        break;
    };

    lua_pushfstring(L, ": %p", p);
    lua_concat(L, 3);

    return 1;
}

static int packet_index(lua_State* L) {
    struct packet* p = luaL_checkudata(L, 1, PACKET_MT);
    const char* n = luaL_checkstring(L, 2);
    int is_get = lua_gettop(L) == 2;

#define FIELD(name, var, bitsize, ntoh, hton) \
    do { \
        if (strcmp(n, name) == 0) { \
            if (is_get) { \
                lua_pushnumber(L, ntoh(var)); \
                return 1; \
            } else { \
                uint32_t v = hton(luaL_checknumber(L, 3)); \
                if ((bitsize) > 0) { \
                    uint64_t mask = ((((uint64_t)1) << ((bitsize) + 1)) - 1); \
                    if ((v & ~mask) != 0) { \
                        luaL_error(L, "bad value"); \
                    } \
                } \
                var = v; \
                return 0; \
            } \
        } \
    } while(0)

    FIELD("dir", p->dir, 1, , );
    FIELD("from_id", p->from_id, 0, , );

#define FIELD_IP_INT(name, bitsize)    FIELD(#name, p->hdr.ip_##name, bitsize, ,)
#define FIELD_IP_IP(name)              FIELD(#name, p->hdr.ip_##name.s_addr, 32, ntohl, htonl)

    FIELD_IP_INT(hl, 4);
    FIELD_IP_INT(v, 4);
    FIELD_IP_INT(tos, 8);
    FIELD_IP_INT(len, 16);
    FIELD_IP_INT(id, 16);
    FIELD_IP_INT(off, 16);
    FIELD_IP_INT(ttl, 8);
    FIELD_IP_INT(p, 8);
    FIELD_IP_INT(sum, 16);
    FIELD("saddr", p->hdr.ip_src.s_addr, 32, ntohl, htonl);
    FIELD("daddr", p->hdr.ip_dst.s_addr, 32, ntohl, htonl);

    void* payload = packet_ip_payload(p, NULL);

    switch (p->hdr.ip_p) {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        {
            uint16_t* p_sport = (((uint16_t*)payload)+0);
            uint16_t* p_dport = (((uint16_t*)payload)+1);

            FIELD("sport", *p_sport, 16, ntohs, htons);
            FIELD("dport", *p_dport, 16, ntohs, htons);
        }
        break;

    case IPPROTO_ICMP:
        {
            struct icmphdr* icmp = payload;

            FIELD("icmp_type", icmp->type, 8, , );
            FIELD("icmp_echo_id", icmp->un.echo.id, 16, ntohs, htons);
        }
        break;
    }

#undef FIELD
#undef FIELD_IP_INT
#undef FIELD_IP_IP

    return 0;
    //return luaL_error(L, "unknown field: %s", n);
}

static void install_packet(lua_State* L) {

#define GLOBAL(v)   \
    do { \
        lua_pushnumber(L, v); \
        lua_setglobal(L, #v); \
    } while(0)

    GLOBAL(UP);
    GLOBAL(DOWN);
    GLOBAL(ICMP_ECHO);
    GLOBAL(ICMP_ECHOREPLY);
    GLOBAL(IPPROTO_ICMP);
    GLOBAL(IPPROTO_TCP);
    GLOBAL(IPPROTO_UDP);

#undef GLOBAL

    luaL_newmetatable(L, PACKET_MT);

    lua_pushcfunction(L, packet_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, packet_index);
    lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, packet_tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pop(L, 1);
}

int load_config(const char* confpath) {
    int err;
    assert(confpath);

    L = luaL_newstate();
    if (!L) {
        ERROR("luaL_newstate");
        err = -1;
        goto finally;
    }

    luaL_openlibs(L);

    lua_pushglobaltable(L);

    lua_pushcfunction(L, _now);
    lua_setfield(L, -2, "now");
    lua_pushcfunction(L, _subnet);
    lua_setfield(L, -2, "subnet");
    lua_pushcfunction(L, _randomwan);
    lua_setfield(L, -2, "randomwan");
    lua_pushcfunction(L, _alloc_nodes);
    lua_setfield(L, -2, "_alloc_nodes");
    lua_pushcfunction(L, _peer);
    lua_setfield(L, -2, "_peer");
    lua_pushcfunction(L, _link);
    lua_setfield(L, -2, "_link");
    lua_pushcfunction(L, _nat);
    lua_setfield(L, -2, "_nat");
    lua_pushcfunction(L, _wan);
    lua_setfield(L, -2, "_wan");

    install_packet(L);

    int status = luaL_loadbuffer(L, _luacode_server, _luacode_server_sz, "server.lua");
    if (status == LUA_OK) {
        status = docall(L, 0, 0);
    }

    if (status == LUA_OK) {
        status = luaL_loadfile(L, confpath);
    }

    if (status == LUA_OK) {
        status = docall(L, 0, 0);
    }

    if (status == LUA_OK) {
        lua_pushglobaltable(L);
        lua_getfield(L, -1, "_build");
        status = docall(L, 0, 0);
    }

    if (status != LUA_OK) {
        fprintf(stderr, "cannot load confpath: %s\n",
            lua_tostring(L, -1)
        );
        err = -1;
        goto finally;
    }

    err = 0;
finally:
    return err;
}

/////

static void help(char* arg0) {
    fprintf(stderr,
        "Usage: %s [OPTS] <CONFPATH>\n"
        "\n"
        "Ooptions:\n"
        "  -h                   Print this screen and quit\n",
        arg0
    );
}

int main_read(int argc, char* argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':
        default:
            help(argv[0]);
            return EXIT_FAILURE;
        };
    }

    if (optind >= argc) {
        fprintf(stderr, "configuration required\n");
        help(argv[0]);
        return EXIT_FAILURE;
    }

    const char* confpath = argv[optind];

    if (load_config(confpath) < 0) {
        fprintf(stderr, "cannot load conf. abort\n");
        return EXIT_FAILURE;
    }

    for (unsigned int i=1; i<=nodes_max; ++i) {
        struct node* n = NODE(i);

        printf("%d\t%s\t%d\n", n->id, n->type, n->up);
    }


    if (L) lua_close(L), L = NULL;

    return EXIT_SUCCESS;
}

