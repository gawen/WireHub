#ifndef WIREHUB_KEY_H
#define WIREHUB_KEY_H

#include "common.h"

int genkey(uint8_t* ed25519_sk, const char* key, int workbit, int num_threads);
int auth_packet(uint8_t* p, size_t ml, const uint8_t* sk, const uint8_t* pk);
int verify_packet(const uint8_t* p, size_t pl, const uint8_t* sk);
unsigned int workbit(const uint8_t* pk, const void* k, size_t l);

#endif  // WIREHUB_KEY_H

