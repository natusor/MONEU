/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
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

#ifndef __RAND_H__
#define __RAND_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_INSECURE_PRNG
void random_reseed(const uint32_t value);
#endif

void random_buffer(uint8_t *buf, size_t len);

/* Verify the generator actually produces varying output. Fills a buffer
 * repeatedly until every byte position has been non-zero at least once,
 * giving up after a bounded number of tries.
 *
 * This does not measure randomness quality - nothing cheap can. It catches
 * the catastrophic case: an environment where the entropy source returns
 * constant or zero bytes, which has happened in stripped-down containers
 * and on misconfigured virtual machines. Bitcoin Core runs the same check
 * at start-up for the same reason.
 *
 * Returns 0 on success, non-zero if the generator looks broken. Call once
 * during start-up, before any key is generated. */
int random_sanity_check(void);

/* Mix extra entropy into everything this generator produces from now on.
 *
 * The kernel is always the base source: output is derived from a fresh
 * kernel draw with the extra material folded in, never from the extra
 * material alone. Adding to a hash cannot take entropy away, so this can
 * only help and can never make the generator worse than the kernel.
 *
 * The point is future hardware. A node with a quantum or atmospheric
 * source can feed it here without any change to consensus - the network
 * sees only keys and addresses, never where their randomness came from. */
void random_refeed(const uint8_t *extra, size_t len);

static inline uint32_t random32(void) {
    uint32_t r = 0;
    random_buffer((uint8_t *)&r, sizeof(r));
    return r;
}

uint32_t random_uniform(uint32_t n);
void random_permute(char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
