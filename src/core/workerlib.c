#include "luawh.h"
#include <unistd.h>
#include <pthread.h>
#include "serdes.h"

#define MT  "worker"

struct pipefd {
    int r_fd;
    int w_fd;
};

struct worker {
    struct pipefd req, resp;
    volatile int running;
    char* name;
    lua_State* L;
    pthread_t thread;
};

static int _tostring(lua_State* L) {
    struct worker* w = luaW_toptr(L, 1, MT);

    if (w) {
        lua_pushfstring(L, "worker* '%s': %p", w->name, w);
    } else {
        lua_pushstring(L, "worker*: <dangling>");
    }

    return 1;
}


static void delete_worker(struct worker* w) {
    if (w->running) {
        char type_b = LUA_TNONE;
        assert(write(w->req.w_fd, &type_b, 1) == 1);
        pthread_join(w->thread, NULL);
    }

    if (w->req.r_fd != -1) { close(w->req.r_fd), w->req.r_fd = -1; }
    if (w->req.w_fd != -1) { close(w->req.w_fd), w->req.w_fd = -1; }
    if (w->resp.r_fd != -1) { close(w->resp.r_fd), w->resp.r_fd = -1; }
    if (w->resp.w_fd != -1) { close(w->resp.w_fd), w->resp.w_fd = -1; }
    if (w->name) { free(w->name), w->name = NULL; }
    if (w->L) { lua_close(w->L), w->L = NULL; }
    if (w->name) { free(w->name), w->name = NULL; }

    free(w);
}

static void delete_worker_pvoid(void* w) {
    return delete_worker((struct worker*)w);
}

static void* worker(void* ud) {
    struct worker* w = ud;
    lua_State* L = w->L;

    for (;;) {
        lua_settop(L, 0);

        int success = luaW_readstack(L, w->req.r_fd) == 0;

        if (success && lua_gettop(L) < 2) {
            break;
        }

        success &= lua_pcall(L, lua_gettop(L)-2, LUA_MULTRET, 0) == LUA_OK;
        lua_pushboolean(L, success);
        lua_insert(L, 2);
        luaW_writestack(L, 1, w->resp.w_fd);
    }

    luaW_writestack(L, 1, w->resp.w_fd);
    w->running = 0;

    return NULL;
}

int luawh_pushworker(lua_State* L) {
    const char* name = lua_tostring(L, 1);

    struct worker* w = calloc(1, sizeof(struct worker));
    assert(w);

    w->name = name ? strdup(name) : NULL;
    w->req.r_fd = w->req.w_fd = -1;
    w->resp.r_fd = w->resp.w_fd = -1;

    if (pipe((int*)&w->req)) {
        delete_worker(w);
        luaL_error(L, "pipe() failed: %s", strerror(errno));
    }

    if (pipe((int*)&w->resp)) {
        delete_worker(w);
        luaL_error(L, "pipe() failed: %s", strerror(errno));
    }

    w->L = luaL_newstate();
    luaL_openlibs(w->L);

    if (pthread_create(&w->thread, NULL, worker, w)) {
        delete_worker(w);
        luaL_error(L, "pthread_create() failed: %s", strerror(errno));
    }

    w->running = 1;

    luaW_pushptr(L, MT, w);
    return 1;
}

static int _pushwork(lua_State* L) {
    struct worker* w = luaW_checkptr(L, 1, MT);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    luaL_checktype(L, 3, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    lua_pushinteger(L, ref);
    lua_replace(L, 2);
    luaW_writestack(L, 2, w->req.w_fd);

    return 0;
}

static int _update(lua_State* L) {
    struct worker* w = luaW_checkptr(L, 1, MT);
    luaL_checktype(L, 2, LUA_TTABLE);
    lua_pushinteger(L, w->resp.r_fd);
    lua_seti(L, 2, luaL_len(L, 2)+1);

    return 0;
}

static int _on_readable(lua_State* L) {
    struct worker* w = luaW_checkptr(L, 1, MT);
    luaL_checktype(L, 2, LUA_TTABLE);

    lua_pushinteger(L, w->resp.r_fd);
    lua_gettable(L, 2);

    if (lua_toboolean(L, -1)) {
        lua_settop(L, 1);

        if (luaW_readstack(L, w->resp.r_fd) != 0) {
            luaL_error(L, "deserialization failed");
        }

        lua_pushvalue(L, 2);
        lua_gettable(L, LUA_REGISTRYINDEX);
        assert (lua_type(L, -1) == LUA_TFUNCTION);
        lua_replace(L, 2);
        lua_call(L, lua_gettop(L)-2, 0);
    }

    return 0;
}

LUAMOD_API int luaopen_worker(lua_State* L) {
    luaW_declptr(L, MT, delete_worker_pvoid);

    luaL_getmetatable(L, MT);
    lua_getfield(L, -1, "__index");

    lua_pushcfunction(L, _pushwork);
    lua_setfield(L, -2, "pcall");

    lua_pushcfunction(L, _update);
    lua_setfield(L, -2, "update");

    lua_pushcfunction(L, _on_readable);
    lua_setfield(L, -2, "on_readable");

    lua_pop(L, 1);

    lua_pushcfunction(L, _tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pop(L, 1);

    lua_pushcfunction(L, luawh_pushworker);

    return 1;
}

