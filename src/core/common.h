#ifndef WIREHUB_COMMON_H
#define WIREHUB_COMMON_H

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <pcap.h>
#include <sodium.h>
*/
/*** CONSTANTS ***************************************************************/

#define crypto_scalarmult_curve25519_KEYBASE64BYTES 44

static const uint8_t wh_pkt_hdr[] = {0xff, 0x00, 0x00, 0x00};
static const int wh_version[3] = {0, 1, 0};

#endif  // WIREHUB_COMMON_H

