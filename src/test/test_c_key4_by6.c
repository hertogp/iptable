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
#include "test_c_key4_by6.h"

void
test_key4_by6_good(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];
    uint8_t d=0x0b;

    /* construct an ipv6 key ::11.12.13.14 */
    *ip6 = IP6_KEYLEN;
    for (int i=1; i < IP6_KEYLEN; i++)
      *(ip6+i) = i < IP6_KEYLEN-4 ? 0x00 : d++;

    /* ip4 derived from ipv6 --> simpy it's last 4 bytes */
    for (int i=0; i < IP4_KEYLEN; i++)
      *(ip4+i) = 0xff;  /* all one's so we can test for changes */

    mu_assert(key4_by6(ip4, ip6));
    mu_assert(*ip4 == IP4_KEYLEN);
    mu_eq(*(ip4+1), 0x0b, "byte 0x%02x");
    mu_eq(*(ip4+2), 0x0c, "byte 0x%02x");
    mu_eq(*(ip4+3), 0x0d, "byte 0x%02x");
    mu_eq(*(ip4+4), 0x0e, "byte 0x%02x");
}

void
test_key4_by6_bad(void)
{
    uint8_t ip4[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];

    /* A few corner cases where we expect key4_by6 to fail by returning 0 */

    /* invalid ipv6 key, keylen too large */
    *ip6 = IP6_KEYLEN + 1;
    mu_assert(key4_by6(ip4, ip6) == 0);

    /* invalid ipv6 key, keylen too small */
    *ip6 = IP6_KEYLEN - 1;
    mu_assert(key4_by6(ip4, ip6) == 0);

    /* invalid ipv6 key, keylen is zero (still too small) */
    *ip6 = 0;
    mu_assert(key4_by6(ip4, ip6) == 0);

    /* and is not fooled by a 255 as keylength (way too big) */
    *ip6 = 0xff;;
    mu_assert(key4_by6(ip4, ip6) == 0);

}
