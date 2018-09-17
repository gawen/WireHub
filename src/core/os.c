#include "common.h"
#include <time.h>

uint64_t now_seconds(void) {
    return time(NULL);
}

