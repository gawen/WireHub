#include "luawh.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int ipc_prepare(void) {
    return system("mkdir -p " WH_DEFAULT_SOCKPATH " 2> /dev/null");
}

static int ipc_sockaddr_un(struct sockaddr_un* addr_un, const char* interface) {
    addr_un->sun_family = AF_UNIX;

    ssize_t sz = snprintf(
        addr_un->sun_path, sizeof(addr_un->sun_path),
        WH_DEFAULT_SOCKPATH "%s.sock", interface
    );

    if (sz < 0 || (size_t)sz >= sizeof(addr_un->sun_path)) {
        return -1;
    }

    return 0;
}

static int ipc_unlink(const char* interface) {
    struct sockaddr_un addr_un;
    if (ipc_sockaddr_un(&addr_un, interface) < 0) {
        return -1;
    }

    if (unlink(addr_un.sun_path) < 0) {
        return -1;
    }

    return 0;
}

static int ipc_bind(const char* interface, int force) {
    int sock = -1;

    struct sockaddr_un addr_un;
    if (ipc_sockaddr_un(&addr_un, interface) < 0) {
        goto err;
    }

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        goto err;
    }

    int bind_ret;
    if ((bind_ret = bind(sock, (struct sockaddr*)&addr_un, sizeof(addr_un))) < 0) {
        if (errno == EADDRINUSE && force) {
            if (unlink(addr_un.sun_path) < 0) {
                goto err;
            }

            bind_ret = bind(sock, (struct sockaddr*)&addr_un, sizeof(addr_un) < 0);
        }

        if (bind_ret < 0) {
            goto err;
        }
    }

    if (listen(sock, 1) < 0) {
        goto err;
    }

    return sock;
err:
    if (sock != -1) {
        close(sock);
    }
    return -1;
}

static int ipc_connect(const char* interface) {
    int sock = -1;

    struct sockaddr_un addr_un;
    if (ipc_sockaddr_un(&addr_un, interface) < 0) {
        goto err;
    }

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        goto err;
    }

    if (connect(sock, (struct sockaddr*)&addr_un, sizeof(addr_un)) < 0) {
        goto err;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
        goto err;
    }

    return sock;
err:
    if (sock != -1) {
        close(sock);
    }

    return -1;
}

static int ipc_list(int(*cb)(const char*, void*), void* ud) {
    DIR* dirp;
    int ret = 0;

    if ((dirp = opendir(WH_DEFAULT_SOCKPATH)) == NULL) {
        return -1;
    }

    struct dirent* dp;
    while ((dp = readdir(dirp))) {
        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s%s", WH_DEFAULT_SOCKPATH, dp->d_name);

        struct stat st;
        if (stat(fullpath, &st) < 0) {
            continue;
        }

        if (!S_ISSOCK(st.st_mode)) {
            continue;
        }

        // remove folder's path and suffix '.sock'
        char* ext = strstr(dp->d_name, ".sock");
        if (!ext) {
            continue;
        }
        *ext = 0;

        int ret = cb(dp->d_name, ud);
        if (ret < 0) {
            break;
        }
    }

    closedir(dirp), dirp = NULL;
    return ret;
}

static int ipc_accept(int sock) {
    int new_sock = -1;
    if ((new_sock = accept(sock, NULL, NULL)) < 0) {
        return -1;
    }

    if (fcntl(new_sock, F_SETFL, fcntl(new_sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
        goto err;
    }

    return new_sock;

err:
    if (new_sock == -1) {
        close(new_sock);
    }

    return -1;
}

static int _ipc_prepare(lua_State* L) {
    if (ipc_prepare() < 0) {
        luaL_error(L, "prepare ipc failed: %s", strerror(errno));
    }

    return 0;
}

static int _ipc_connect(lua_State* L) {
    const char* interface = luaL_checkstring(L, 1);

    int sock;
    if ((sock = ipc_connect(interface)) < 0) {
        switch (errno) {
        case ENOENT: return 0;
        default: luaL_error(L, "connect ipc failed(): %s", strerror(errno));
        };
    }

    luaW_pushfd(L, sock);
    return 1;
}

static int _ipc_unlink(lua_State* L) {
    const char* interface = lua_tostring(L, lua_upvalueindex(1));
    assert(interface);

    lua_pushboolean(L, ipc_unlink(interface) >= 0);
    return 1;
}

static int _ipc_bind(lua_State* L) {
    const char* interface = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TBOOLEAN);
    int force = lua_toboolean(L, 2);

    int sock;
    if ((sock = ipc_bind(interface, force)) < 0) {
        luaL_error(L, "connect ipc failed(): %s", strerror(errno));
    }

    luaW_pushfd(L, sock);
    lua_pushstring(L, interface);
    lua_pushcclosure(L, _ipc_unlink, 1);
    return 2;
}

static int _ipc_accept(lua_State* L) {
    int sock = luaW_getfd(L, 1);

    int new_sock;
    if ((new_sock = ipc_accept(sock)) < 0) {
        luaL_error(L, "connect ipc failed(): %s", strerror(errno));
    }

    luaW_pushfd(L, new_sock);
    return 1;
}

static int _ipc_list_cb(const char* name, void* ud) {
    lua_State* L = ud;

    lua_pushstring(L, name);
    lua_seti(L, -2, luaL_len(L, -2)+1);

    return 0;
}

static int _ipc_list(lua_State* L) {
    lua_newtable(L);
    if (ipc_list(_ipc_list_cb, L) && errno != ENOENT) {
        luaL_error(L, "IPC list failed: %s", strerror(errno));
    }
    return 1;
}

static const luaL_Reg funcs[] = {
    {"accept", _ipc_accept},
    {"bind", _ipc_bind},
    {"connect", _ipc_connect},
    {"prepare", _ipc_prepare},
    {"list", _ipc_list},
    {NULL, NULL},
};

LUAMOD_API int luaopen_ipc(lua_State* L) {
    luaL_checkversion(L);
    luaL_newlib(L, funcs);
    return 1;
}

