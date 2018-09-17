#ifndef WIREHUB_PACKET_H
#define WIREHUB_PACKET_H

#include "common.h"

#include <sodium.h>

#define packet_flags_TIMEMASK       (((uint64_t)-1) >> 1)
#define packet_flags_TIMESHIFT      0
#define packet_flags_DIRECTMASK     0x1
#define packet_flags_DIRECTSHIFT    63

#define packet_hdr(p)   (p+0)
#define packet_src(p)   (packet_hdr(p)+4)
#define packet_flags_time(p)  (packet_src(p)+crypto_scalarmult_curve25519_BYTES)
#define packet_body(p)   (packet_flags_time(p)+8)
#define packet_mac(p,l) (packet_body(p)+l)

static inline size_t packet_size(size_t l) {
    return (
        4 +
        crypto_scalarmult_curve25519_BYTES +
        //crypto_scalarmult_curve25519_BYTES +
        8 +
        l +
        crypto_auth_hmacsha512256_BYTES
    );
}

int auth_packet(uint8_t* p, size_t l, const uint8_t* sk, const uint8_t* pk);
int verify_packet(const uint8_t* p, size_t pl, const uint8_t* sk);

#endif  // PACKET_H

