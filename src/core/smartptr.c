#include "luawh.h"

static const char* _registry_field = "ptrmt";

static int _free(lua_State* L) {
    void** pp = lua_touserdata(L, 1);
    void(*del)(void*) = lua_touserdata(L, lua_upvalueindex(1));

    if (*pp) {
        del(*pp), *pp = NULL;
    }

    return 0;
}

static int _tostring(lua_State* L) {
    void** pp = lua_touserdata(L, 1);

    lua_getmetatable(L, 1);
    lua_getfield(L, -1, "mt");
    lua_remove(L, -2);

    if (*pp) {
        lua_pushfstring(L, "*: %p", *pp);
    } else {
        lua_pushstring(L, "*: <dangling>");
    }
    lua_concat(L, 2);

    return 1;
}

static void _newmt(lua_State* L, const char* mt, void(*del)(void*)) {
    if (luaL_newmetatable(L, mt)) {
        // build metatable
        lua_pushstring(L, mt);
        lua_setfield(L, -2, "mt");

        lua_newtable(L);    // __index

        lua_pushlightuserdata(L, del);
        lua_pushcclosure(L, _free, 1);
        lua_pushvalue(L, -1);
        lua_setfield(L, -3, "free");
        lua_setfield(L, -3, "__gc");
        lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, _tostring);
        lua_setfield(L, -2, "__tostring");

        // lazy build of the registry's field
        if (lua_getfield(L, LUA_REGISTRYINDEX, _registry_field) == LUA_TNIL) {
            lua_pop(L, 1);
            lua_newtable(L);
            lua_pushvalue(L, -1);
            lua_setfield(L, LUA_REGISTRYINDEX, _registry_field);
        }

        // register metatable as a pointer's
        lua_pushvalue(L, -2);
        lua_pushboolean(L, 1);
        lua_settable(L, -3);
        lua_pop(L, 1);
    }
}

void luaW_declptr(lua_State* L, const char* mt, void(*del)(void*)) {
    _newmt(L, mt, del);
    lua_pop(L, 1);
}

void luaW_pushptr(lua_State* L, const char* mt, void* ptr) {
    void** pp = lua_newuserdata(L, sizeof(void*));
    *pp = ptr;

    // free is given as a default deleter. if type was previously declared, free
    // will be ignored
    _newmt(L, mt, free);
    lua_setmetatable(L, -2);
}

static void* getptr(lua_State* L, int idx, const char* mt, int error, int own) {
    void **pp = luaL_testudata(L, idx, mt);
    if (!pp) {
        if (error) {
            luaL_error(L, "bad type (pointer %s expected, got %s)", mt,
                    lua_typename(L, idx));
        } else {
            return NULL;
        }
    }

    void *p = *pp;
    if (!p) {
        if (error) {
            luaL_error(L, "dangling pointer #%d", idx);
        } else {
            return NULL;
        }
    }

    if (own) {
        *pp = NULL;
    }

    return p;
}

void* luaW_checkptr(lua_State* L, int idx, const char* mt) {
    luaL_checkudata(L, idx, mt);
    return getptr(L, idx, mt, 1, 0);
}

void* luaW_ownptr(lua_State* L, int idx, const char* mt) {
    return getptr(L, idx, mt, 1, 1);
}

void* luaW_toptr(lua_State* L, int idx, const char* mt) {
    return getptr(L, idx, mt, 0, 0);
}


