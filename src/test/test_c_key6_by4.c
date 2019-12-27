#include <stdio.h>
#include <sys/types.h>       // required for u_char
#include <stddef.h>          // offsetof
#include <stdlib.h>          // malloc
#include <netinet/in.h>      // sockaddr_in
#include <arpa/inet.h>       // inet_pton and friends
#include <string.h>          // strlen
#include <ctype.h>           // isdigit

#include "radix.h"           // the radix tree
#include "iptable.h"         // iptable layered on top of radix.c

#include "minunit.h"         // the mu_test macros
#include "test_c_key6_by4.h"

void
test_key6_by4_good(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];
    int compat = 0, offset=IP6_KEYLEN - 6;

    /* construct ipv4 key 11.12.13.14 */
    *ip4 = IP4_KEYLEN;
    for (int i = 1; i < IP4_KEYLEN; i++)
      *(ip4+i) = (0x0a + i) & 0xff;


    /* ip6 with v4mapped ipv4 --> ::ffff:11.12.13.14 */
    for (int i = 0; i < IP6_KEYLEN; i++)
      *(ip6+i) = 0xff;  /* all one's so we can test for zero's */
    *(ip6+offset) = 0x00;  /* key6_by4 should set these */
    *(ip6+offset+1) = 0x00;

    mu_assert(key6_by4(ip6, ip4, compat));
    mu_assert(*ip6 == IP6_KEYLEN);
    for (int i = 1; i < offset; i++)
      mu_eq(*(ip6+i), 0x00, "byte 0x%02x");
    mu_eq(*(ip6+offset+0), 0xff, "byte 0x%02x");
    mu_eq(*(ip6+offset+1), 0xff, "byte 0x%02x");
    mu_eq(*(ip6+offset+2), 0x0b, "byte 0x%02x");
    mu_eq(*(ip6+offset+3), 0x0c, "byte 0x%02x");
    mu_eq(*(ip6+offset+4), 0x0d, "byte 0x%02x");
    mu_eq(*(ip6+offset+5), 0x0e, "byte 0x%02x");


    /* ip6 with v4compat ipv4 --> ::0000:11.12.13.14 */
    compat = 1;
    for (int i = 0; i < IP6_KEYLEN; i++)
      *(ip6+i) = 0xff;  /* all one's so we can test for zero's */

    mu_assert(key6_by4(ip6, ip4, compat));
    mu_assert(*ip6 == IP6_KEYLEN);
    for (int i = 1; i < offset; i++)
      mu_eq(*(ip6+i), 0x00, "byte 0x%02x");
    mu_eq(*(ip6+offset+0), 0x00, "byte 0x%02x");
    mu_eq(*(ip6+offset+1), 0x00, "byte 0x%02x");
    mu_eq(*(ip6+offset+2), 0x0b, "byte 0x%02x");
    mu_eq(*(ip6+offset+3), 0x0c, "byte 0x%02x");
    mu_eq(*(ip6+offset+4), 0x0d, "byte 0x%02x");
    mu_eq(*(ip6+offset+5), 0x0e, "byte 0x%02x");

}

void
test_key6_by4_bad(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];

    /* A few corner cases where we expect key6_by4 to fail by returning 0 */

    /* invalid ipv4 key, keylen too large */
    *ip4 = IP4_KEYLEN + 1;
    mu_assert(key6_by4(ip6, ip4, 1) == 0);  /* fail in compat mode */
    mu_assert(key6_by4(ip6, ip4, 0) == 0);  /* and in mapped mode */

    /* invalid ipv4 key, keylen too small */
    *ip4 = IP4_KEYLEN - 1;
    mu_assert(key6_by4(ip6, ip4, 1) == 0);  /* fail in compat mode */
    mu_assert(key6_by4(ip6, ip4, 0) == 0);  /* and in mapped mode */

    /* invalid ipv4 key, keylen is zero (still too small) */
    *ip4 = 0;
    mu_assert(key6_by4(ip6, ip4, 1) == 0);  /* fail in compat mode */
    mu_assert(key6_by4(ip6, ip4, 0) == 0);  /* and in mapped mode */

    /* and is not fooled by a valid ip6 keylength (still too big) */
    *ip4 = IP6_KEYLEN;
    mu_assert(key6_by4(ip6, ip4, 1) == 0);  /* fail in compat mode */
    mu_assert(key6_by4(ip6, ip4, 0) == 0);  /* and in mapped mode */

    /* and is not fooled by a 255 as keylength (way too big) */
    *ip4 = 0xff;;
    mu_assert(key6_by4(ip6, ip4, 1) == 0);  /* fail in compat mode */
    mu_assert(key6_by4(ip6, ip4, 0) == 0);  /* and in mapped mode */

}
