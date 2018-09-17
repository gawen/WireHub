#include "packet.h"

int auth_packet(uint8_t* p, size_t l, const uint8_t* sk, const uint8_t* pk) {
    uint8_t k[crypto_scalarmult_curve25519_SCALARBYTES];
    sodium_mlock(k, sizeof(k));

    if (crypto_scalarmult_curve25519(k, sk, pk) != 0) {
        return -1;
    }

    crypto_auth_hmacsha512256(packet_mac(p, l), p, packet_mac(p, l)-p, k);

    sodium_munlock(k, sizeof(k));

    return 0;
}

int verify_packet(const uint8_t* p, size_t pl, const uint8_t* sk) {
    if (pl<packet_size(0)) {
        return -1;
    }

    if (memcmp(packet_hdr(p), wh_pkt_hdr, sizeof(wh_pkt_hdr)) != 0) {
        return -1;
    }

    size_t l = pl-packet_size(0);

    uint8_t k[crypto_scalarmult_curve25519_SCALARBYTES];
    sodium_mlock(k, sizeof(k));
    if (crypto_scalarmult_curve25519(k, sk, packet_src(p))) {
        return -1;
    }

    int r = crypto_auth_hmacsha512256_verify(packet_mac(p, l), p, packet_mac(p, l)-p, k);
    sodium_munlock(k, sizeof(k));

    return r;
}

