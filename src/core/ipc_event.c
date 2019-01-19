#include "luawh.h"

#define MT  "ipc_event"

struct ipc_event {
    int fds[2];
};

static int _set(lua_State* L) {
    struct ipc_event* pe = luaW_checkptr(L, 1, MT);

    if (write(pe->fds[1], "\x2a", 1) < 0) {
        luaL_error(L, "write() failed: %s", strerror(errno));
    }

    return 0;
}

static int _clear(lua_State* L) {
    struct ipc_event* pe = luaW_checkptr(L, 1, MT);

    char buf[128];
    if (read(pe->fds[0], buf, sizeof(buf)) < 0) {
        luaL_error(L, "read() failed: %s", strerror(errno));
    }

    return 0;
}

static void _delete(void* ud) {
    struct ipc_event* pe = ud;

    close(pe->fds[0]);
    close(pe->fds[1]);
    free(pe);
}

static int _close(lua_State* L) {
    struct ipc_event* pe = luaW_ownptr(L, 1, MT);

    _delete(pe);
    return 0;
}

static int _fd(lua_State* L) {
    struct ipc_event* pe = luaW_checkptr(L, 1, MT);
    lua_pushinteger(L, pe->fds[0]);
    return 1;
}

static int _new(lua_State* L) {
    int fds[2];
    if (pipe(fds)) {
        luaL_error(L, "pipe() failed: %s", strerror(errno));
    }

    struct ipc_event* pe = malloc(sizeof(struct ipc_event));
    pe->fds[0] = fds[0];
    pe->fds[1] = fds[1];
    luaW_pushptr(L, MT, pe);

    return 1;
}

static const luaL_Reg funcs[] = {
    {"clear", _clear},
    {"close", _close},
    {"get_fd", _fd},
    {"new", _new},
    {"set", _set},
    {NULL, NULL},
};

LUAMOD_API int luaopen_ipc_event(lua_State* L) {
    luaL_checkversion(L);
    luaL_newlib(L, funcs);

    luaW_declptr(L, MT, _delete);

    return 1;
}

