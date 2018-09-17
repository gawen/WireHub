#include "common.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/limits.h>

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

int ipc_unlink(const char* interface) {
    struct sockaddr_un addr_un;
    if (ipc_sockaddr_un(&addr_un, interface) < 0) {
        return -1;
    }

    if (unlink(addr_un.sun_path) < 0) {
        return -1;
    }

    return 0;
}

int ipc_bind(const char* interface, int force) {
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

int ipc_connect(const char* interface) {
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

int ipc_list(int(*cb)(const char*, void*), void* ud) {
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

int ipc_accept(int sock) {
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

