#include "net.h"
#include <sodium.h>

void orchid(struct address* a, const void* cid, size_t cid_sz, const void* m, size_t l, uint16_t port) {
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash_state s;
    crypto_generichash_init(&s, NULL, 0, sizeof(hash));
    crypto_generichash_update(&s, (const void*)cid, cid_sz);
    crypto_generichash_update(&s, (const void*)m, l);
    crypto_generichash_final(&s, hash, sizeof(hash));

    a->sa_family = a->in6.sin6_family = AF_INET6;
    a->in6.sin6_port = htons(port);

    // XXX RFC 4843 states to get the middle 100-bit-long bitstring from the
    // hash

    assert(sizeof(a->in6.sin6_addr) <= crypto_generichash_BYTES);
    memcpy((uint8_t*)&a->in6.sin6_addr, hash, sizeof(a->in6.sin6_addr));
    ((uint8_t*)&a->in6.sin6_addr)[0] = 0x20;
    ((uint8_t*)&a->in6.sin6_addr)[1] = 0x01;
    ((uint8_t*)&a->in6.sin6_addr)[2] &= 0x0f;
    ((uint8_t*)&a->in6.sin6_addr)[2] |= 0x10;
}


