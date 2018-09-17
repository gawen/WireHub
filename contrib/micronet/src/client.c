#include <netinet/if_ether.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include "common.h"

#define UNET_DEFAULT_SERVERNAME "micronet.server"
#define UNET_ENV_SERVERNAME "UNET_SERVERNAME"

#define UNET_DEFAULT_IFNAME "micronet"
#define UNET_ENV_IFNAME     "UNET_IFNAME"

static char subnet[64] = { 0 };
static char gateway[INET_ADDRSTRLEN+1];
static char tun_name[IFNAMSIZ];
static const char* server_port = UNET_STR(DEFAULT_SERVER_PORT);
static int mtu;
static int node_id;
static int server_fd;
static int tun_fd;
static struct addrinfo* server_addr;

static inline uint32_t _subnet_mask(int cidr) {
    assert(0 <= cidr && cidr <= 32);
    if (cidr == 32) {
        return 0xffffffff;
    }

    return ((1 << cidr)-1) << (32-cidr);
}

static int get_server_addr(void) {
    const char* server_name = getenv(UNET_ENV_SERVERNAME);
    if (!server_name) server_name = UNET_DEFAULT_SERVERNAME;
    assert(server_name);

    struct addrinfo hint;
    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_flags = 0;

    int ret;
    if ((ret = getaddrinfo(server_name, server_port, &hint, &server_addr)) < 0) {
        fprintf(stderr, "unknown host '%s':'%s': %s\n", server_name, server_port, gai_strerror(ret));
        return -errno;
    }

    int sock = socket(server_addr->ai_family, server_addr->ai_socktype, server_addr->ai_protocol);

    if (sock < 0) {
        ERROR("socket");
        freeaddrinfo(server_addr), server_addr = NULL;
        return -errno;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
        ERROR("fcntl(... | O_NONBLOCK)");
        close(sock);
        return -errno;
    }

    server_fd = sock;
    return 0;
}

static int create_tunnel(void) {
    mtu = UNET_DEFAULT_MTU;
    const char* mtu_s = getenv(UNET_ENV_MTU);
    if (mtu_s) mtu = atoi(mtu_s);

    const char* ifname = getenv(UNET_ENV_IFNAME);
    if (!ifname) ifname = UNET_DEFAULT_IFNAME;

    if (mtu < 576) {
        fprintf(stderr, "MTU smaller than 576\n");
        return -EINVAL;
    }

    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        ERROR("open(\"/dev/net/tun\")");
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        ERROR("ioctl(TUNSETIFF)");
        close(fd);
        return -errno;
    }

    memcpy(tun_name, ifr.ifr_name, IFNAMSIZ);
    fprintf(stderr, "micronet tun ifname: %s\n", ifr.ifr_name);

    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        ERROR("fcntl(... | O_NONBLOCK)");
        close(fd);
        return -errno;
    }

    tun_fd = fd;
    return 0;
}

static int configure_net(void) {
    char cmd[128];

    snprintf(cmd, sizeof(cmd), "echo > /etc/resolv.conf");
    if (system(cmd) < 0) {
        return -errno;
    }

    snprintf(cmd, sizeof(cmd), "ip link set dev %s mtu %d", tun_name, mtu);
    if (system(cmd) < 0) {
        return -errno;
    }

    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", subnet, tun_name);
    if (system(cmd) < 0) {
        return -errno;
    }

    snprintf(cmd, sizeof(cmd), "ip link set %s up", tun_name);
    if (system(cmd) < 0) {
        return -errno;
    }

    if (strcmp(gateway, "0.0.0.0") == 0) {
        snprintf(cmd, sizeof(cmd), "ip route replace default dev %s", tun_name);
    } else {
        snprintf(cmd, sizeof(cmd), "ip route replace default via %s", gateway);
    }
    if (system(cmd) < 0) {
        return -errno;
    }

    printf("interface %s up, local addr is %s, gateway is %s.\n", tun_name, subnet, gateway);
    return 0;
}

static int sendto_server(struct iovec* iov, int iovlen) {
    struct msghdr m;
    m.msg_name = server_addr->ai_addr;
    m.msg_namelen = server_addr->ai_addrlen;
    m.msg_iov = iov;
    m.msg_iovlen = iovlen;
    m.msg_control = 0;
    m.msg_controllen = 0;
    m.msg_flags = 0;

    return sendmsg(server_fd, &m, 0);
}

static int loop() {
    uint32_t nid = htonl(node_id);

    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        ERROR("epool_create1");
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
        ERROR("epoll_ctl");
        close(epollfd);
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        ERROR("epoll_ctl");
        close(epollfd);
        return -1;
    }

#define SENDTO_SERVER(iov, iovlen) \
    do { \
        if (sendto_server(iov, iovlen) < 0) { \
            ret = -errno; \
            ERROR("sendto_server"); \
            break; \
        } \
    } while(0)

    const int buf_sz = 64 * 1024;
    uint8_t* buf = malloc(buf_sz);
    assert(buf);

    if (subnet[0] != 0 && configure_net() < 0) {
        ERROR("configure_net");
        close(epollfd);
        return -1;
    }

    const int max_events = 10;
    struct epoll_event events[max_events];
    int ret = 0;
    int first_loop = 1;
    for (;;) {
        int timeout = -1;

        if (first_loop) {
            timeout = 0;
        } else if (subnet[0] == 0) {
            timeout = 1 * 1000;
        }

        first_loop = 0;

        int nfds = epoll_wait(epollfd, events, max_events, timeout);
        if (nfds < 0) {
            switch (errno) {
            case EINTR:
                continue;
            };

            ret = -errno;
            ERROR("epoll_wait");
            break;
        }

        int n;
        for (n=0; n<nfds; ++n) {
            while (events[n].data.fd == tun_fd) {
                ssize_t sz = read(tun_fd, buf, buf_sz);

                if (sz < 0 && errno == EAGAIN) {
                    break;
                }

                if (sz < 0) {
                    ret = -errno;
                    ERROR("read");
                    break;
                }

                struct iovec iov[2];
                iov[0].iov_base = &nid;
                iov[0].iov_len = sizeof(nid);
                iov[1].iov_base = buf;
                iov[1].iov_len = sz;

                SENDTO_SERVER(iov, 2);

            }

            while (events[n].data.fd == server_fd) {
                ssize_t sz = recvfrom(server_fd, buf, buf_sz, 0, NULL, 0);

                if (sz < 0 && errno == EAGAIN) {
                    break;
                }

                if (sz < 0) {
                    ret = -errno;
                    ERROR("recvfrom");
                    break;
                }

                if (subnet[0] == 0) {
                    if (sz == 4+4+1) {
                        // 0-4: ip
                        // 4-8: gw
                        // 8-9: cidr

                        char ip[INET_ADDRSTRLEN+1];
                        inet_ntop(AF_INET, buf, ip, sizeof(ip)-1);
                        inet_ntop(AF_INET, buf+4, gateway, sizeof(gateway)-1);

                        uint8_t cidr = buf[4+4];
                        if (32 < cidr) {
                            ERROR("cidr");
                            ret = -EINVAL;
                            break;
                        }

                        snprintf(subnet, sizeof(subnet), "%s/%d", ip, cidr);
                        if (configure_net() < 0) {
                            ERROR("configure_net");
                            ret = -1;
                            break;
                        }
                    }

                } else if (write(tun_fd, buf, sz) < 0) {
                    ret = -errno;
                    ERROR("write");
                    break;
                }
            }
        }

        if (nfds == 0) {
            struct iovec iov[1];
            iov[0].iov_base = &nid;
            iov[0].iov_len = sizeof(nid);

            SENDTO_SERVER(iov, 1);
        }
    }

#undef SENDTO_SERVER

    free(buf);
    close(epollfd);
    return ret;
}

/***/

static void help(char* arg0) {
    fprintf(stderr,
        "Usage: %s [OPTS] <ID>\n"
        "\n"
        "Ooptions:\n"
        "  -h                   Print this screen and quit\n",
        arg0
    );
}

int main_client(int argc, char* argv[]) {
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
        fprintf(stderr, "ID required\n");
        help(argv[0]);
        return EXIT_FAILURE;
    }
    const char* id_s = argv[optind];
    node_id = atoi(id_s);

    if (node_id <= 0) {
        fprintf(stderr, "ID must be set strictly greater to 0\n");
        return EXIT_FAILURE;
    }

    if (get_server_addr() < 0) {
        fprintf(stderr, "could not resolve server. abort\n");
        return EXIT_FAILURE;
    }

    if (create_tunnel() < 0) {
        freeaddrinfo(server_addr), server_addr = NULL;
        fprintf(stderr, "could not create tunnel. abort\n");
        return EXIT_FAILURE;
    }

    //strcpy(subnet, "192.168.42.2/24"); strcpy(gateway, "192.168.42.1");
    loop();

    close(tun_fd);
    freeaddrinfo(server_addr), server_addr = NULL;

    return EXIT_SUCCESS;
}

