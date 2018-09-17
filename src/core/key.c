// XXX protect secret data (sodium_malloc, sodium_mlock)

#include "common.h"
#include <pthread.h>
#include <sodium.h>

int trailing_0s_buf(const void* buf, size_t l) {
    assert(l % sizeof(uint32_t) == 0);
    unsigned int i;
    unsigned int r = 0;
    for(i=0; i<l; i += sizeof(uint32_t)) {
        int t0 = __builtin_clz(be32toh(*((const uint32_t*)buf+i)));
        r += t0;
        if (t0 < 32) {
            break;
        }
    }
    return r;
}

unsigned int workbit(const uint8_t* pk, const void* k, size_t l) {
    unsigned char hash[crypto_generichash_BYTES];

    crypto_generichash_state s;
    crypto_generichash_init(&s, NULL, 0, sizeof(hash));
    crypto_generichash_update(&s, pk, crypto_scalarmult_curve25519_BYTES);
    crypto_generichash_update(&s, k, l);
    crypto_generichash_final(&s, hash, sizeof(hash));

    return trailing_0s_buf(hash, sizeof(hash));
}

struct stat_st {
    time_t now;
    volatile uint64_t count;
};

struct search_st {
    struct stat_st* stat;

    const uint8_t* k;
    size_t klen;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    volatile int found;
    unsigned int wb;
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES];
    unsigned char hash[crypto_generichash_BYTES];
};

static int search(struct search_st* s) {
    assert(s);

    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    size_t tohash_l = crypto_scalarmult_curve25519_BYTES + s->klen;
    unsigned char* tohash = alloca(tohash_l);
    unsigned char hash[crypto_generichash_BYTES];

    memcpy(tohash+crypto_scalarmult_curve25519_BYTES, s->k, s->klen);

    for (int i=0; !s->found; ++i) {
        if (i == 256) {
            __sync_add_and_fetch(&s->stat->count, i);
            i = 0;
        }

        crypto_sign_ed25519_keypair(ed25519_pk, ed25519_sk);

        // pk should be positive
        if ((ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES-1] & 0x80) == 0x80) {
            continue;
        }

        // convert to curve25519 point
        if (crypto_sign_ed25519_pk_to_curve25519(tohash, ed25519_pk) < 0) {
            continue;
        }

        crypto_generichash(hash, sizeof(hash), tohash, tohash_l, NULL, 0);

        unsigned int wb = trailing_0s_buf(hash, sizeof(hash));

        if (wb >= s->wb) {
            if (crypto_sign_ed25519_sk_to_curve25519(s->x25519_sk, ed25519_sk) < 0) {
                continue;
            }

            pthread_mutex_lock(&s->mutex);

            if (!s->found) {
                // found!
                s->found = 1;

                memcpy(s->ed25519_pk, ed25519_pk, sizeof(ed25519_pk));
                memcpy(s->ed25519_sk, ed25519_sk, sizeof(ed25519_sk));
                memcpy(s->x25519_pk, tohash, crypto_scalarmult_curve25519_BYTES);
                memcpy(s->hash, hash, sizeof(hash));
                s->wb = wb;

                pthread_cond_broadcast(&s->cond);
            }

            pthread_mutex_unlock(&s->mutex);
            break;
        }
    }

    return 0;
}

static void* worker(void* ud) {
    struct search_st* s = (struct search_st*)ud;

    search(s);

    pthread_exit(NULL);
    return NULL;
}

int genkey(
    uint8_t* ed25519_sk,
    const char* key,
    int wb,
    int num_threads
) {
    int err = 0;
    struct stat_st stat;
    memset(&stat, 0, sizeof(stat));

    struct search_st s = {
        .stat = &stat,
        .k = (const uint8_t*)key,
        .klen = strlen(key),
        .wb = wb,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
        .found = 0,
    };

    pthread_t* threads = calloc(num_threads, sizeof(pthread_t));

    pthread_mutex_lock(&s.mutex);
    for (int i=0; i<num_threads; ++i) {
        if (pthread_create(&threads[i], NULL, worker, &s)) {
            err = -1;
            goto finally;
        }
    }

#if 1
    pthread_cond_wait(&s.cond, &s.mutex);
#else
    time(&stat.now);
    uint64_t last_count = 0;
    int anim_i = 0;
    for (;;) {
        int duration = time(NULL) - stat.now;
        uint64_t count = stat.count;
        uint64_t diff_count = count - last_count;
        last_count = count;
        uint64_t h_per_s = diff_count;

        if (h_per_s > 0) {
            anim_i = (anim_i + 1) % (sizeof(anim));
        }

        fprintf(stderr, "        \r%c generating %dworkbit key for '%s' (%.1fkK/s, %ds)",
            anim[anim_i],
            s.wb,
            s.k,
            (double)h_per_s/1000.0,
            duration
        );

        fflush(stdout);

        struct timespec to;

        clock_gettime(CLOCK_REALTIME, &to);
        to.tv_sec += 1;

        int retval = pthread_cond_timedwait(&s.cond, &s.mutex, &to);

        if (retval == 0) {
            break;
        } else if (retval != ETIMEDOUT) {
            err = -1;
            goto finally;
        }
    }
#endif

    memcpy(ed25519_sk, s.ed25519_sk, crypto_sign_ed25519_SECRETKEYBYTES);
    pthread_mutex_unlock(&s.mutex);

    assert(err == 0);
finally:
    for (int i=0; i<num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    if (threads) free(threads);

    return err;
}

