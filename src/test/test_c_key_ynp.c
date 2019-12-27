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
#include "test_c_key_ynp.h"

void
test_key_ynp_good(void)
{
    uint8_t buf[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];
    uint8_t *p;

    /* key_ynp(dst, src, offset, nbytes), where src must be a valid key
     * Note: key_ynp requires src to be a pointer to the LEN-byte of the key
     * since it uses that to guard against reading too far.
     * No such check is done for writing to the dst buffer!
     */

    /* construct an ipv6 key [17]0102:0304:...:1516 */
    *ip6 = IP6_KEYLEN;
    for (int i=1; i < IP6_KEYLEN; i++)  /* ip6: [17]0102:...:1516 */
      *(ip6+i) = i & 0xff;
    for (int i=0; i < MAX_BINKEY; i++)  /* buf: [0,0,...0] */
      *(buf+i) = 0x00;

    /* yank/paste 5 bytes from start */
    p = key_ynp(buf, ip6, 0, 5);   /* yank/paste 1st 5 bytes */
    mu_assert(p != NULL);
    mu_eq(0x11, *(buf+0), "LEN 0x%02x");
    mu_eq(0x01, *(buf+1), "byte 0x%02x");
    mu_eq(0x02, *(buf+2), "byte 0x%02x");
    mu_eq(0x03, *(buf+3), "byte 0x%02x");
    mu_eq(0x04, *(buf+4), "byte 0x%02x");
    mu_eq(0x00, *p, "byte 0x%02x");       /* p->next free byte in buf */
    mu_eq(5, (int)(p - buf), "offset %d");

    /* yank/paste 6 bytes from the middle */
    for (int i=0; i < MAX_BINKEY; i++)  /* buf: [0,0,...0] */
      *(buf+i) = 0x00;
    p = key_ynp(buf, ip6, 5, 6);
    mu_assert(p != NULL);
    mu_eq(0x05, *(buf+0), "byte 0x%02x");
    mu_eq(0x06, *(buf+1), "byte 0x%02x");
    mu_eq(0x07, *(buf+2), "byte 0x%02x");
    mu_eq(0x08, *(buf+3), "byte 0x%02x");
    mu_eq(0x09, *(buf+4), "byte 0x%02x");
    mu_eq(0x0a, *(buf+5), "byte 0x%02x");
    mu_eq(*p, 0x00, "byte 0x%02x");       /* p->next free byte in buf */
    mu_eq(6, (int)(p - buf), "offset %d");

    /* yank/paste last 4 bytes */
    for (int i=0; i < MAX_BINKEY; i++)  /* buf: [0,0,...0] */
      *(buf+i) = 0x00;
    p = key_ynp(buf, ip6, IP6_KEYLEN-4, 4);
    mu_assert(p != NULL);
    mu_eq(0x0d, *(buf+0), "byte 0x%02x");
    mu_eq(0x0e, *(buf+1), "byte 0x%02x");
    mu_eq(0x0f, *(buf+2), "byte 0x%02x");
    mu_eq(0x10, *(buf+3), "byte 0x%02x");
    mu_eq(4, (int)(p - buf), "offset %d");

    /* yank/past entire key */
    p = key_ynp(buf, ip6, 0, *ip6);
    mu_assert(p != NULL);
    for (int i=0; i < IP6_KEYLEN; i++)
      mu_eq(*(buf+i), *(ip6+i), "bytes 0x%02x");
    mu_eq(IP6_KEYLEN, (int)(p - buf), "offset %d");
}

void
test_key_ynp_bad(void)
{
    uint8_t buf[MAX_BINKEY];
    uint8_t ip6[MAX_BINKEY];

    /* key_ynp(dst, src, offset, nbytes), where src must be a valid key */

    /* construct an ipv6 key [17]0102:0304:...:1516 */
    *ip6 = IP6_KEYLEN;
    for (int i=1; i < IP6_KEYLEN; i++)  /* ip6: [17]0102:...:1516 */
      *(ip6+i) = i & 0xff;
    /* zero out the receiving buffer */
    for (int i=0; i < MAX_BINKEY; i++)  /* buf: [0,0,...0] */
      *(buf+i) = 0x00;

    /* no NULL values allowed */
    mu_assert(key_ynp(NULL, ip6, 0, 1) == NULL);
    mu_assert(key_ynp(buf, NULL, 0, 1) == NULL);

    /* no negative offset, num-of-bytes allowed */
    mu_assert(key_ynp(buf, ip6, -1, 1) == NULL);
    mu_assert(key_ynp(buf, ip6, 1, -1) == NULL);

    /* no going past the src keylen */
    mu_assert(key_ynp(buf, ip6, 0, 18) == NULL);
    mu_assert(key_ynp(buf, ip6, 1, 17) == NULL);
    mu_assert(key_ynp(buf, ip6, 17, 1) == NULL);

}
