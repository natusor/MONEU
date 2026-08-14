#ifndef __BYTE_ORDER_H__
#define __BYTE_ORDER_H__

// FROM sha2.h:
/*
 * BYTE_ORDER NOTE:
 *
 * Please make sure that your system defines BYTE_ORDER.  If your
 * architecture is little-endian, make sure it also defines
 * LITTLE_ENDIAN and that the two (BYTE_ORDER and LITTLE_ENDIAN) are
 * equivalent.
 *
 * If your system does not define the above, then you can do so by
 * hand like this:
 *
 *   #define LITTLE_ENDIAN 1234
 *   #define BIG_ENDIAN    4321
 *
 * And for little-endian machines, add:
 *
 *   #define BYTE_ORDER LITTLE_ENDIAN
 *
 * Or for big-endian machines:
 *
 *   #define BYTE_ORDER BIG_ENDIAN
 *
 * The FreeBSD machine this was written on defines BYTE_ORDER
 * appropriately by including <sys/types.h> (which in turn includes
 * <machine/endian.h> where the appropriate definitions are actually
 * made).
 */

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
// Detected, not assumed.
//
// Defaulting to LITTLE_ENDIAN here silently disarmed the guard sha2.c
// raises two headers later, so on a big-endian machine every hash in the
// system would come out different with nothing said about it. GCC and
// Clang always define __BYTE_ORDER__, so the answer is available; where it
// is not, the build stops rather than guessing.
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    defined(__ORDER_BIG_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#error "Unsupported __BYTE_ORDER__"
#endif
#else
#error "BYTE_ORDER is not defined and cannot be detected; define it explicitly"
#endif
#endif

#define REVERSE32(w, x)                                              \
  {                                                                  \
    uint32_t tmp = (w);                                              \
    tmp = (tmp >> 16) | (tmp << 16);                                 \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
  }

#define REVERSE64(w, x)                           \
  {                                               \
    uint64_t tmp = (w);                           \
    tmp = (tmp >> 32) | (tmp << 32);              \
    tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) |  \
          ((tmp & 0x00ff00ff00ff00ffULL) << 8);   \
    (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
          ((tmp & 0x0000ffff0000ffffULL) << 16);  \
  }

#endif
