/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2025-2026 natusor (MONEU)
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "rand.h"
#include "sha2.h"
#include "memzero.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__)
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define MONEU_HAVE_GETRANDOM 1
#endif
#endif

/* Optional extra entropy, folded into every draw once supplied.
 *
 * Kept deliberately small and write-only from the outside: it is never a
 * source on its own, only an addition to a fresh kernel draw. A userspace
 * pool that replaced the kernel would be a step backwards on this platform
 * - it could be written to disk, cloned with a virtual machine or captured
 * in a core dump, none of which apply to the kernel's own pool. */
static uint8_t  gExtra[32];
static int      gHaveExtra = 0;
static pthread_mutex_t gExtraLock = PTHREAD_MUTEX_INITIALIZER;

/* Read len bytes from the kernel.
 *
 * getrandom() is preferred over opening /dev/urandom: it needs no file
 * descriptor, so it cannot fail because the process ran out of them, and
 * it cannot be fooled by a chroot without a populated /dev. The device is
 * kept as a fallback for kernels too old to have the call. */
static void kernel_random(uint8_t *buf, size_t len) {
    size_t filled = 0;

#ifdef MONEU_HAVE_GETRANDOM
    while (filled < len) {
        long r = syscall(SYS_getrandom, buf + filled, len - filled, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;   /* fall through to the device */
        }
        filled += (size_t)r;
    }
    if (filled == len) return;
#endif

    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f) {
            fprintf(stderr, "FATAL: no entropy source available\n");
            abort();
        }
        size_t got = fread(buf + filled, 1, len - filled, f);
        fclose(f);
        if (got != len - filled) {
            fprintf(stderr, "FATAL: entropy read failed (%zu/%zu bytes)\n",
                    filled + got, len);
            abort();
        }
    }
}

void random_buffer(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return;

    kernel_random(buf, len);

    /* Nothing extra supplied: the kernel draw is the answer. */
    pthread_mutex_lock(&gExtraLock);
    const int haveExtra = gHaveExtra;
    pthread_mutex_unlock(&gExtraLock);
    if (!haveExtra) return;

    /* Fold the extra material in, 32 bytes at a time. The kernel draw goes
     * into the hash too, so the result is at least as unpredictable as the
     * kernel alone whatever the extra material turns out to be worth. */
    {
        size_t done = 0;
        uint32_t counter = 0;
        while (done < len) {
            uint8_t block[SHA256_DIGEST_LENGTH];
            SHA256_CTX ctx;
            sha256_Init(&ctx);

            pthread_mutex_lock(&gExtraLock);
            sha256_Update(&ctx, gExtra, sizeof(gExtra));
            pthread_mutex_unlock(&gExtraLock);

            sha256_Update(&ctx, buf + done,
                          (uint32_t)((len - done < SHA256_DIGEST_LENGTH)
                                     ? (len - done) : SHA256_DIGEST_LENGTH));
            sha256_Update(&ctx, (const uint8_t *)&counter, sizeof(counter));
            sha256_Final(&ctx, block);
            memzero(&ctx, sizeof(ctx));

            size_t take = (len - done < SHA256_DIGEST_LENGTH)
                          ? (len - done) : SHA256_DIGEST_LENGTH;
            memcpy(buf + done, block, take);
            memzero(block, sizeof(block));
            done += take;
            counter++;
        }
    }
}

void random_refeed(const uint8_t *extra, size_t len) {
    if (!extra || len == 0) return;

    uint8_t mixed[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    pthread_mutex_lock(&gExtraLock);
    /* Chain onto whatever was supplied before, so successive feeds
     * accumulate instead of replacing one another. */
    sha256_Update(&ctx, gExtra, sizeof(gExtra));
    sha256_Update(&ctx, extra, (uint32_t)len);
    sha256_Final(&ctx, mixed);
    memcpy(gExtra, mixed, sizeof(gExtra));
    gHaveExtra = 1;
    pthread_mutex_unlock(&gExtraLock);

    memzero(&ctx, sizeof(ctx));
    memzero(mixed, sizeof(mixed));
}

int random_sanity_check(void) {
    /* Loop until every byte position has been non-zero at least once. A
     * working generator needs a handful of rounds; one returning constants
     * never gets there. */
    enum { MAX_TRIES = 1024, SAMPLE = 32 };
    uint8_t data[SAMPLE];
    int seen[SAMPLE];
    int tries = 0;
    int i;
    int total = 0;

    for (i = 0; i < SAMPLE; ++i) seen[i] = 0;

    do {
        memset(data, 0, sizeof(data));
        random_buffer(data, sizeof(data));
        for (i = 0; i < SAMPLE; ++i) {
            if (data[i] != 0) seen[i] = 1;
        }
        total = 0;
        for (i = 0; i < SAMPLE; ++i) total += seen[i];
        tries++;
    } while (total < SAMPLE && tries < MAX_TRIES);

    memzero(data, sizeof(data));

    if (total < SAMPLE) {
        fprintf(stderr,
                "FATAL: entropy source looks broken - only %d of %d byte "
                "positions ever varied over %d draws\n",
                total, SAMPLE, tries);
        return 1;
    }
    return 0;
}

uint32_t random_uniform(uint32_t n) {
  // A modulus of zero would divide by zero below. No caller passes it, but
  // the function is public and answering 0 for a range of nothing is the
  // only sensible thing to do.
  if (n == 0) return 0;
    uint32_t x = 0;
    uint32_t max = 0xFFFFFFFF - (0xFFFFFFFF % n);
    while ((x = random32()) >= max);
    return x / (max / n);
}

void random_permute(char *str, size_t len) {
    for (int i = len - 1; i >= 1; i--) {
        int j = random_uniform(i + 1);
        char t = str[j];
        str[j] = str[i];
        str[i] = t;
    }
}
