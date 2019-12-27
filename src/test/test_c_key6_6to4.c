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
#include "test_c_key6_6to4.h"

void
test_key6_6to4_good(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];

    /* construct an ipv4 key 11.12.13.14 */
    *ip4 = IP4_KEYLEN;
    for (int i = 1; i < IP4_KEYLEN; i++)
      *(ip4+i) = (0x0a + i) & 0xff;

    /* ip6 derived from ipv4 --> 2002:V4ADDR:: */
    for (int i = 0; i < IP6_KEYLEN; i++)
      *(ip6+i) = 0xff;  /* all one's so we can test for changes */

    mu_assert(key6_6to4(ip6, ip4));
    mu_assert(*ip6 == IP6_KEYLEN);
    mu_eq(*(ip6+1), 0x20, "byte 0x%02x");
    mu_eq(*(ip6+2), 0x02, "byte 0x%02x");
    mu_eq(*(ip6+3), 0x0b, "byte 0x%02x");
    mu_eq(*(ip6+4), 0x0c, "byte 0x%02x");
    mu_eq(*(ip6+5), 0x0d, "byte 0x%02x");
    mu_eq(*(ip6+6), 0x0e, "byte 0x%02x");
    for (int i = 7; i < IP6_KEYLEN; i++)
      mu_eq(*(ip6+i), 0x00, "byte 0x%02x");
}

void
test_key6_6to4_bad(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];

    /* A few corner cases where we expect key6_6to4 to fail by returning 0 */

    /* keylen too large */
    *ip4 = IP4_KEYLEN + 1;
    mu_assert(key6_6to4(ip6, ip4) == 0);

    /* keylen too small */
    *ip4 = IP4_KEYLEN - 1;
    mu_assert(key6_6to4(ip6, ip4) == 0);

    /* keylen is zero (still too small) */
    *ip4 = 0;
    mu_assert(key6_6to4(ip6, ip4) == 0);

    /* key is a valid ip6 keylength but invalid ipv4 keylen */
    *ip4 = IP6_KEYLEN;
    mu_assert(key6_6to4(ip6, ip4) == 0);

    /* keylen is 255 (way too big) */
    *ip4 = 0xff;;
    mu_assert(key6_6to4(ip6, ip4) == 0);

}
