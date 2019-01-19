#ifndef LUAWH_H
#define LUAWH_H

#include "common.h"
#include "net.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int luaW_version(lua_State *L);

void* luaW_newsecret(lua_State* L, size_t len);
void* luaW_tosecret(lua_State* L, int idx, size_t len);
void* luaW_checksecret(lua_State* L, int idx, size_t len);
void* luaW_ownsecret(lua_State* L, int idx, size_t len);
void luaW_freesecret(void* p);

// declare a pointer
// example: luaW_declptr(L, "buffer", free);
void luaW_declptr(lua_State* L, const char* mt, void(*del)(void*));
// push a pointer. pointer is not owned after the call
// example: luaW_pushptr(L, "buffer", malloc(1024));
void luaW_pushptr(lua_State* L, const char* mt, void* ptr);
// returns pointer after checking it. raises an error if bad type or pointer is
// dangling
// example: luaW_checkptr(L, -1, "buffer");
void* luaW_checkptr(lua_State* L, int idx, const char* mt);
// returns pointer after checking it. returns null if pointer is dangling
// example: luaW_toptr(L, -1, "buffer")
void* luaW_toptr(lua_State* L, int idx, const char* mt);
// as luaW_checkptr, but owns the pointer
// example: luaW_ownptr(L, -1, "buffer");
void* luaW_ownptr(lua_State* L, int idx, const char* mt);

struct address* luaW_newaddress(lua_State* L);

static inline uint16_t luaW_checkport(lua_State* L, int idx) {
    lua_Number port_n = luaL_checkinteger(L, idx);

    if (port_n < 0 || UINT16_MAX < port_n) {
        luaL_error(L, "bad port: %d", port_n);
    }

    return (uint16_t)port_n;
}

void luaW_pushfd(lua_State* L, int fd);
int luaW_getfd(lua_State* L, int idx);

LUAMOD_API int luaopen_ipc(lua_State* L);
LUAMOD_API int luaopen_ipc_event(lua_State* L);
LUAMOD_API int luaopen_tun(lua_State* L);
LUAMOD_API int luaopen_wg(lua_State* L);
LUAMOD_API int luaopen_whcore(lua_State* L);
LUAMOD_API int luaopen_worker(lua_State* L);

#if WH_ENABLE_MINIUPNPC
LUAMOD_API int luaopen_upnp(lua_State* L);
#endif

#endif  // LUAWH_H

