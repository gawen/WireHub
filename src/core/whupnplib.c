#include "luawh.h"

#if WH_ENABLE_MINIUPNPC

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

static const char* mt = "device_igd";

struct device_igd {
    struct UPNPUrls urls;
    struct IGDdatas data;
    int type;
};

static int _discover_igd(lua_State* L) {
	int delay_ms = luaL_checknumber(L, 1) * 1000;
    int upnp_err = 0;
    struct UPNPDev* devices = upnpDiscover(delay_ms, NULL, NULL, UPNP_LOCAL_PORT_ANY, 0, 2, &upnp_err);

    if (upnp_err != 0) {
        luaL_error(L, "upnpDiscover failed(): %d", upnp_err);
    }

    if (!devices) {
        return 0;
    }

    struct device_igd* d = lua_newuserdata(L, sizeof(struct device_igd));
    luaL_newmetatable(L, mt);
    lua_setmetatable(L, -2);

    char lanaddr[64] = "";
    int ret = UPNP_GetValidIGD(devices, &d->urls, &d->data, lanaddr, sizeof(lanaddr));

    if (ret < 0) {
        luaL_error(L, "UPNP_GetValidIGD failed(): %d", ret);
    }

    if (ret == 0) {
        return 0;
    }

    d->type = ret;

    if (lanaddr[0]) {
        lua_pushstring(L, lanaddr);
    } else {
        lua_pushnil(L);
    }

    lua_pushstring(L, d->urls.controlURL);

    return 3;
}

static int _external_ip(lua_State* L) {
    struct device_igd* d = luaL_checkudata(L, 1, mt);
    char ip[40];

    int r = UPNP_GetExternalIPAddress(d->urls.controlURL, d->data.first.servicetype, ip);

    if (r != UPNPCOMMAND_SUCCESS) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "GetExternalIPAddress() failed: %d (%s)",
            r, strupnperror(r)
        );
        return 2;
    }

    lua_pushboolean(L, 1);
    lua_pushstring(L, ip);
    return 2;
}

static int _list_redirects(lua_State* L) {
    struct device_igd* d = luaL_checkudata(L, 1, mt);

    lua_newtable(L);

    for (int i = 0; ; ++i) {
        char index[16];
        snprintf(index, sizeof(index), "%d", i);

        char int_client[40] = "";
        char int_port[16] = "";
        char ext_port[16] = "";
        char protocol[4] = "";
        char desc[80] = "";
        char enabled[16] = "";
        char host[64] = "";
        char duration[16] = "";


        int ret = UPNP_GetGenericPortMappingEntry(
            d->urls.controlURL, d->data.first.servicetype, index, ext_port,
            int_client, int_port, protocol, desc, enabled, host, duration
        );

        if (ret != 0) {
            break;
        }

        lua_newtable(L);

#define lua_pushstringnumber(L, s) \
        do { \
            if (lua_stringtonumber(L, s) == 0) { \
                lua_pushnil(L); \
            } \
        } while(0)

        for (char* c=protocol; *c; ++c) {
            *c = tolower(*c);
        }

        lua_pushstring(L, protocol);
        lua_setfield(L, -2, "protocol");

        lua_pushstringnumber(L, ext_port);
        lua_setfield(L, -2, "eport");

        lua_pushstring(L, int_client);
        lua_setfield(L, -2, "iaddr");

        lua_pushstringnumber(L, int_port);
        lua_setfield(L, -2, "iport");

        lua_pushstring(L, desc);
        lua_setfield(L, -2, "desc");

        lua_pushstring(L, host);
        lua_setfield(L, -2, "host");

        lua_pushstringnumber(L, duration);
        lua_setfield(L, -2, "lease");

#undef lua_pushstringnumber

        lua_seti(L, -2, i+1);
    }

    return 1;
}

static int _add_redirect(lua_State* L) {
    struct device_igd* d = luaL_checkudata(L, 1, mt);
    luaL_checktype(L, 2, LUA_TTABLE);

    lua_getfield(L, -1, "protocol");
    const char* protocol_const = lua_tostring(L, -1);
    if (!protocol_const) { luaL_error(L, "field 'protocol' is nil"); }
    char protocol[8];
    strncpy(protocol, protocol_const, sizeof(protocol)-1);
    for (char* c=protocol; *c; ++c) { *c = toupper(*c); }

    lua_pop(L, 1);

    lua_getfield(L, -1, "eport");
    char ext_port[6];
    snprintf(ext_port, sizeof(ext_port), "%d", luaW_checkport(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, -1, "iport");
    char int_port[6];
    snprintf(int_port, sizeof(int_port), "%d", luaW_checkport(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, -1, "iaddr");
    const char* int_client = lua_tostring(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, -1, "lease");
    char lease[16];
    snprintf(lease, sizeof(lease), "%lld", lua_tointeger(L, -1));
    lua_pop(L, 1);

    lua_getfield(L, -1, "desc");
    const char* desc = lua_tostring(L, -1);
    lua_pop(L, 1);

    if (!int_client) { luaL_error(L, "field 'iaddr', is nil"); }

    int ret = UPNP_AddPortMapping(
        d->urls.controlURL, d->data.first.servicetype, ext_port, int_port,
        int_client, desc, protocol, NULL, lease
    );

    if (ret != UPNPCOMMAND_SUCCESS) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "AddPortMapping(%s, %s, %s) failed: %d (%s)",
            ext_port, int_port, int_client, ret, strupnperror(ret)
        );
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int _remove_redirect(lua_State* L) {
    struct device_igd* d = luaL_checkudata(L, 1, mt);
    luaL_checktype(L, 2, LUA_TTABLE);

    lua_getfield(L, -1, "protocol");
    const char* protocol_const = lua_tostring(L, -1);
    if (!protocol_const) { luaL_error(L, "field 'protocol' is nil"); }
    char protocol[8];
    strncpy(protocol, protocol_const, sizeof(protocol)-1);
    for (char* c=protocol; *c; ++c) { *c = toupper(*c); }
    lua_pop(L, 1);

    lua_getfield(L, -1, "eport");
    char ext_port[6];
    snprintf(ext_port, sizeof(ext_port), "%d", luaW_checkport(L, -1));
    lua_pop(L, 1);

    int ret = UPNP_DeletePortMapping(
        d->urls.controlURL, d->data.first.servicetype, ext_port, protocol, NULL
    );

    if (ret != UPNPCOMMAND_SUCCESS) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "DeletePortMapping(%s, %s) failed: %d (%s)",
            ext_port, protocol, ret, strupnperror(ret)
        );
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static const luaL_Reg funcs[] = {
    { "discover_igd", _discover_igd },
    { "external_ip", _external_ip },
    { "list_redirects", _list_redirects },
    { "add_redirect", _add_redirect },
    { "remove_redirect", _remove_redirect },
    { NULL, NULL}
};

LUAMOD_API int luaopen_whupnp(lua_State* L) {
    luaL_checkversion(L);

    luaL_newlib(L, funcs);

    return 1;
}

#endif  // WH_ENABLE_MINIUPNPC

