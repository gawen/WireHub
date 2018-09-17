#ifndef WIREHUB_MEM_H
#define WIREHUB_MEM_H

static inline void* memdup(const void* p, size_t len) {
    void* n = malloc(len);
    assert(n);
    memcpy(n, p, len);
    return n;
}

#endif  // WIREHUB_MEM_H


