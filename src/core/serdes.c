#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "serdes.h"
#include "luawh.h"

struct load_ud {
    int fd;
    size_t sz;
    char buf[256];
};

static const char* _deser_load(lua_State* L, void* data, size_t* psize) {
    (void)L;

    struct load_ud* ld = (struct load_ud*)data;

    *psize = ld->sz;

    if (*psize > sizeof(ld->buf)) {
        *psize = sizeof(ld->buf);
    }

    if (*psize > 0) {
        ssize_t ret = read(ld->fd, ld->buf, *psize);
        assert(ret>=0);
        assert((size_t)ret<=ld->sz);
        *psize = ret;
        ld->sz -= ret;
    }

    return ld->buf;
}

#define READ(var)   assert(read(fd, &var, sizeof(var)) == sizeof(var))
int luaW_read(lua_State* L, int fd) {
    char type_b;
    uint8_t u8;
    size_t sz;
    lua_Number number;
    char* str;
    int load_ret;
    struct load_ud ld;

    READ(type_b);

    switch ((int)type_b) {
    case LUA_TNONE:
        return 0;

    case LUA_TNIL:
        lua_pushnil(L);
        break;

    case LUA_TBOOLEAN:
        READ(u8);
        lua_pushboolean(L, u8);
        break;

    case LUA_TNUMBER:
        READ(number);
        lua_pushnumber(L, number);
        break;

    case LUA_TSTRING:
        READ(sz);
        // XXX stream?
        str = malloc(sz);
        assert(read(fd, str, sz) == (ssize_t)sz);
        lua_pushlstring(L, str, sz);
        free(str);
        break;

    case LUA_TTABLE:
        lua_newtable(L);
        for (;;) {
            int r = luaW_read(L, fd);
            if (r == -1) {
                return -1;
            } else if (r == 0) {
                break;
            }

            if (luaW_read(L, fd) < 0) {
                return -1;
            }

            lua_rawset(L, -3);
        }
        break;

    case LUA_TFUNCTION:
        READ(ld.sz);
        ld.fd = fd;
        load_ret = lua_load(L, _deser_load, &ld, "work", NULL);
        if (load_ret != LUA_OK) {
            lua_pushnumber(L, load_ret);
            lua_insert(L, -2);

            while(lua_gettop(L) > 2) {
                lua_remove(L, 1);
            }

            return -1;
        }
        break;

    case LUA_TLIGHTUSERDATA:
    case LUA_TUSERDATA:
    case LUA_TTHREAD:
        assert(0 && "unhandled type");
    };

    return 1;
}

int luaW_readstack(lua_State* L, int fd) {
    int ret;
    while((ret = luaW_read(L, fd)) != 0);
    return ret;
}
#undef READ

#define WRITE(var)  assert(write(fd, &var, sizeof(var)) == sizeof(var))
static int _ser_dump(lua_State *L, const void* b, size_t size, void* ud) {
  (void)L;
  luaL_Buffer* buf = (luaL_Buffer*)ud;
  luaL_addlstring(buf, (const char*)b, size);
  return 0;
}

int luaW_write(lua_State* L, int idx, int fd) {
    char type_b = lua_type(L, idx);
    uint8_t u8;
    lua_Number number;
    size_t sz;
    const char* str;
    luaL_Buffer buf;

    WRITE(type_b);

    switch ((int)type_b) {
    case LUA_TNONE:
        return 0;

    case LUA_TNIL:
        break;

    case LUA_TBOOLEAN:
        u8 = lua_toboolean(L, idx);
        WRITE(u8);
        break;

    case LUA_TNUMBER:
        number = lua_tonumber(L, idx);
        WRITE(number);
        break;

    case LUA_TSTRING:
        str = lua_tolstring(L, idx, &sz);
        WRITE(sz);
        assert(write(fd, str, sz) == (ssize_t)sz);
        break;

    case LUA_TTABLE:
        lua_pushnil(L);  /* first key */
        while (lua_next(L, idx) != 0) {
            assert(luaW_write(L, lua_gettop(L)-1, fd) == 1);
            assert(luaW_write(L, lua_gettop(L), fd) == 1);
            lua_pop(L, 1);
        }
        type_b = LUA_TNONE;
        WRITE(type_b);
        break;

    case LUA_TFUNCTION:
        luaL_buffinit(L, &buf);
        lua_pushvalue(L, idx);
        if (lua_dump(L, _ser_dump, &buf, 0) != 0) {
            return luaL_error(L, "unable to dump given function");
        }
        lua_pop(L, 1);
        luaL_pushresult(&buf);
        str = lua_tolstring(L, -1, &sz);
        WRITE(sz);
        assert(write(fd, str, sz) == (ssize_t)sz);
        lua_pop(L, 1);
        break;

    case LUA_TLIGHTUSERDATA:
    case LUA_TUSERDATA:
    case LUA_TTHREAD:
        luaL_error(L, "unhandled type: %s", lua_typename(L, type_b));
    }

    return 1;
}

void luaW_writestack(lua_State* L, int idx, int fd) {
    if (idx < 0) {
        idx = lua_gettop(L)+idx+1;
    }

    for (; luaW_write(L, idx, fd); ++idx);
}

#undef WRITE

