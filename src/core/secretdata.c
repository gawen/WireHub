#include "luawh.h"
#include <sodium.h>

static const char* mt = "secret";

void* luaW_newsecret(lua_State* L, size_t len) {
    void* p = sodium_malloc(sizeof(size_t) + len);
    size_t *plen = p;
    void* buf = p + sizeof(size_t);

    luaW_declptr(L, mt, sodium_free);
    luaW_pushptr(L, mt, p);

    *plen = len;
    return buf;
}

void* luaW_checksecret(lua_State* L, int idx, size_t len) {
    void* p = luaW_checkptr(L, idx, mt);
    size_t *plen = (size_t*)p;

    if (*plen != len) {
        luaL_error(L, "bad secret size (%d expected, got %d)",
            (int)len,
            (int)*plen
        );
    }

    return p+sizeof(size_t);
}

void* luaW_tosecret(lua_State* L, int idx, size_t len) {
    void* p = luaW_toptr(L, idx, mt);

    if (!p) {
        return NULL;
    }

    size_t *plen = (size_t*)p;
    if (*plen != len) {
        return NULL;
    }

    return p+sizeof(size_t);
}

void* luaW_ownsecret(lua_State* L, int idx, size_t len) {
    void* p = luaW_ownptr(L, idx, mt);
    size_t *plen = (size_t*)p;

    if (*plen != len) {
        luaL_error(L, "bad secret size (%zu expected, got %zu)",
            len,
            *plen
        );
    }

    return p+sizeof(size_t);
}

void luaW_freesecret(void* p) {
    sodium_free(p-sizeof(size_t));
}
