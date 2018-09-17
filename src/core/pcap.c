#include "net.h"

pcap_t* sniff(const char* interface, pcap_direction_t direction, enum sniff_proto proto, const char* expr) {
    assert(interface);
    // expr may be NULL

    pcap_t* h;

    if (!(h=pcap_create(interface, NULL))) {
        return NULL;
    }

    if (pcap_set_timeout(h, 1000)) {
        pcap_close(h);
        return NULL;
    }

    /*const int wh_sniff_buffer_size = 64 * 1024;
    if (pcap_set_buffer_size(h, wh_sniff_buffer_size)) {
        pcap_close(h);
        return NULL;
    }*/

    if (pcap_set_immediate_mode(h, 1)) {
        pcap_close(h);
        return NULL;
    }

    int err = pcap_activate(h);
    if (err != 0) {
        fprintf(stderr, "error: %s\n", pcap_geterr(h));
        pcap_close(h);
        return NULL;
    }

    if (pcap_setnonblock(h, 1, NULL) == PCAP_ERROR) {
        pcap_close(h);
        return NULL;
    }

    if (pcap_setdirection(h, direction) == PCAP_ERROR) {
        pcap_close(h);
        return NULL;
    }

    // XXX COMPILER ASSERT
    assert(sizeof(wh_pkt_hdr)==4);

    char filter_exp[256];
    switch (proto) {
    case SNIFF_PROTO_WG:
        snprintf(filter_exp, sizeof(filter_exp),
            "udp and udp[8] & 0xf8 == 0 and udp[9]==%d and udp[10]==%d and udp[11]==%d%s",
            (int)wh_pkt_hdr[1],
            (int)wh_pkt_hdr[2],
            (int)wh_pkt_hdr[3],
            expr ? expr : ""
        );
        break;

    case SNIFF_PROTO_WH:
        snprintf(filter_exp, sizeof(filter_exp),
            "udp and udp[8]==%d and udp[9]==%d and udp[10]==%d and udp[11]==%d%s",
            (int)wh_pkt_hdr[0],
            (int)wh_pkt_hdr[1],
            (int)wh_pkt_hdr[2],
            (int)wh_pkt_hdr[3],
            expr ? expr : ""
        );
        break;
    };

    struct bpf_program filter;
    const int optimize = 0;
    if (pcap_compile(h, &filter, filter_exp, optimize, 0) == PCAP_ERROR) {
        fprintf(stderr, "error: %s\n", pcap_geterr(h));
        pcap_close(h);
        return NULL;
    }

    int r = pcap_setfilter(h, &filter);
    pcap_freecode(&filter);

    if (r == PCAP_ERROR) {
        pcap_close(h);
        return NULL;
    }

    return h;
}


