#include "server.h"

struct timespec now;
static int server_fd = -1;

static uint32_t ip_chksum_update(uint32_t sum, void* buf_, int count) {
    const uint16_t* buf = (uint16_t*)buf_;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(buf++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t*)buf;
    }

    return sum;
}

static uint16_t ip_chksum_final(uint32_t sum) {
    uint16_t answer = 0;
    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return answer;

}

static inline uint16_t ip_chksum(void* buf, int count) {
    uint32_t sum = 0;
    sum = ip_chksum_update(sum, buf, count);
    return ip_chksum_final(sum);
}

struct ip_pseudohdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t p;
    uint16_t len;
};

void packet_refresh_sum(struct packet* p) {
    size_t payload_sz;
    void* payload = packet_ip_payload(p, &payload_sz);

    p->hdr.ip_sum = 0;
    p->hdr.ip_sum = ip_chksum(&p->hdr, payload - (void*)&p->hdr);

    switch (p->hdr.ip_p) {
    case IPPROTO_UDP:
        ((struct udphdr*)payload)->uh_sum = 0;
        // XXX calculate checksum
        break;

    case IPPROTO_ICMP:
        ((struct icmphdr*)payload)->checksum = 0;
        ((struct icmphdr*)payload)->checksum = ip_chksum(payload, payload_sz);
        break;

    case IPPROTO_TCP:
        // XXX the following block seems to be buggy
        {

            struct ip_pseudohdr h = {
                .src = p->hdr.ip_src.s_addr,
                .dst = p->hdr.ip_dst.s_addr,
                .zero = 0,
                .p = IPPROTO_TCP,
                .len = payload_sz,
            };
            assert(sizeof(h) == 12);

            ((struct tcphdr*)payload)->th_sum = 0;

            uint32_t sum = 0;
            sum = ip_chksum_update(sum, &h, sizeof(h));
            sum = ip_chksum_update(sum, payload, payload_sz);

            ((struct tcphdr*)payload)->th_sum = ip_chksum_final(sum);
        }
        break;
    }
}

static void process_packet(struct node* n, struct packet* p) {
    if (p->hdr.ip_v != 4) {
        DROP(n, p, "not IPv4 packet");
        return;
    }

    if (n->kernel) {
        n->kernel(n, p);
    } else {
        DROP(n, p, "undefined kernel");
    }
}

static void run_node(struct node* n) {
    // XXX add latency simulation
    while (n->pkts_heap) {
        struct packet* p = n->pkts_heap;

        n->pkts_heap = p->next;
        if (!n->pkts_heap) {
            n->pkts_tail = NULL;
        }

        process_packet(n, p);
    }
}

void sendto_id(struct node* from_n, node_id to_id, struct packet* p) {
    if (to_id == NODEID_NULL) {
        DROP(from_n, p, "cannot send to node id 0");
    }

    struct node* to_n = NODE(to_id);
    p->from_id = from_n->id;

    if (to_n->pkts_heap) {
        to_n->pkts_tail->next = p;
    } else {
        to_n->pkts_heap = to_n->pkts_tail = p;
    }
    to_n->pkts_tail = p;

    LOG("-> #%d ", to_id);

    run_node(to_n);
}

void hex(const uint8_t* buf, size_t sz) {
    size_t i;
    for (i=0; i<sz; ++i) {
        if (i > 0 && i % 16 == 0) {
            printf("\n");
        }

        printf("%.2x ", (int)buf[i]);
    }
    printf("\n");
}

void print_packet(FILE* fh, struct packet* p) {
    char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];
    uint16_t sport = 0, dport = 0;
    void* payload = packet_ip_payload(p, NULL);

    assert(inet_ntop(AF_INET, &p->hdr.ip_src, src, sizeof(src)-1));
    assert(inet_ntop(AF_INET, &p->hdr.ip_dst, dst, sizeof(dst)-1));

    char proto[64];
    switch (p->hdr.ip_p) {
    case IPPROTO_UDP:
        strncpy(proto, "udp", sizeof(proto));
        sport = ntohs(((struct udphdr*)payload)->uh_sport);
        dport = ntohs(((struct udphdr*)payload)->uh_dport);
        break;

    case IPPROTO_TCP:
        strncpy(proto, "tcp", sizeof(proto));
        sport = ntohs(((struct tcphdr*)payload)->th_sport);
        dport = ntohs(((struct tcphdr*)payload)->th_dport);
        break;

    case IPPROTO_ICMP:
        strncpy(proto, "icmp", sizeof(proto));
        break;

    default:
        snprintf(proto, sizeof(proto), "0x%.2x", p->hdr.ip_p);
        break;
    }


    fprintf(stderr, "\nXXX %.8x\n", p->hdr.ip_dst.s_addr);

    fprintf(fh,
        "src:%s:%d dst:%s:%d\n"
        "proto: %s\n" ,
        src, sport, dst, dport,
        proto
    );
}

int _udp_sendto(struct sockaddr_in* peer_addr, struct iovec* iov, int iovlen) {
    struct msghdr m;
    m.msg_name = peer_addr;
    m.msg_namelen = sizeof(struct sockaddr_in);
    m.msg_iov = iov;
    m.msg_iovlen = iovlen;
    m.msg_control = 0;
    m.msg_controllen = 0;
    m.msg_flags = 0;

    return sendmsg(server_fd, &m, 0);
}

static void on_packet(struct packet* p, struct sockaddr_in* peer_addr) {
    (void)peer_addr;

    p->id = ntohl(p->id);
    LOG(" ID:%d ", p->id);
    if (nodes_max < p->id) {
        LOG("over limit\n");
        free(p);
        return;
    }

    struct node* n = NODE(p->id);
    if (strcmp(n->type, "peer") != 0) {
        LOG("ERROR: not a peer but a '%s'!\n", n->type);
        free(p);
        return;
    }

    memcpy(&n->addr, peer_addr, sizeof(n->addr));

    LOG("%s ", n->type);

    if (p->sz == 4) {
        LOG("assign? ");
        LOG("returns IP:");
        LOG_ADDR(&n->as.peer.ip.addr);
        LOG("/%d gw:", n->as.peer.ip.cidr);
        LOG_ADDR(&n->as.peer.gw.addr);
        LOG("\n");

        struct iovec iov[3];
        iov[0].iov_base = &n->as.peer.ip.addr;
        iov[0].iov_len = sizeof(n->as.peer.ip.addr);
        iov[1].iov_base = &n->as.peer.gw.addr;
        iov[1].iov_len = sizeof(n->as.peer.gw.addr);
        iov[2].iov_base = &n->as.peer.ip.cidr;
        iov[2].iov_len = sizeof(n->as.peer.ip.cidr);
        _udp_sendto(peer_addr, iov, 3);

        return;
    }

    p->sz -= 4;

    //print_packet(stdout, p);
#if 0
    LOG("hex { \n");
    hex(p->body, p->sz);
    LOG("} ");
#endif

    p->dir = UP;
    sendto_id(n, n->id, p);
}

/***/

static void help(char* arg0) {
    fprintf(stderr,
        "Usage: %s [OPTS] <CONFPATH>\n"
        "\n"
        "Ooptions:\n"
        "  -h                   Print this screen and quit\n",
        arg0
    );
}

int create_server_socket(void) {
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (server_fd < 0) {
        ERROR("socket");
        return -errno;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DEFAULT_SERVER_PORT);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ERROR("bind");
        return -errno;
    }

    if (fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        ERROR("fcntl(... | O_NONBLOCK)");
        close(server_fd);
        return -errno;
    }

    return 0;
}

static int loop() {
    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        ERROR("epool_create1");
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        ERROR("epoll_ctl");
        close(epollfd);
        return -1;
    }

    int ret;
    const int max_events = 10;
    struct epoll_event events[max_events];
    for (;;) {
        int timeout = -1;
        int nfds = epoll_wait(epollfd, events, max_events, timeout);

        clock_gettime(CLOCK_REALTIME, &now);

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
            while (events[n].data.fd == server_fd) {
                struct sockaddr_in peer_addr;
                socklen_t peer_addr_sz = sizeof(peer_addr);
                struct packet* p = calloc(1, sizeof(struct packet));
                ssize_t sz = recvfrom(server_fd, p->buf, sizeof(p->buf), 0, (struct sockaddr*)&peer_addr, &peer_addr_sz);

                if (sz < 0 && errno == EAGAIN) {
                    break;
                }

                if (sz < 0) {
                    ret = -errno;
                    ERROR("recvfrom");
                    break;
                }

                p->sz = sz;
                on_packet(p, &peer_addr);
            }
        }
    }

    return ret;
}

int main_server(int argc, char* argv[]) {
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
        fprintf(stderr, "configuration required\n");
        help(argv[0]);
        return EXIT_FAILURE;
    }

    const char* confpath = argv[optind];

    if (create_server_socket() < 0) {
        fprintf(stderr, "cannot create server sock. abort\n");
        return EXIT_FAILURE;
    }

    if (load_config(confpath) < 0) {
        fprintf(stderr, "cannot load conf. abort\n");
        return EXIT_FAILURE;
    }

    loop();

    close(server_fd);
    if (nodes) {
        for (unsigned int i=1; i<=nodes_max; ++i) {
            struct node* n = NODE(i);
            if (n->type) free(n->type);
        }

        free(nodes);
    }

    if (L) lua_close(L), L = NULL;

    return EXIT_SUCCESS;
}

