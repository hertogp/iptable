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
#include "test_c_key_isin.h"    // a generated header file for this test runner

/*
 * Test key_isin(a, b, m) -> true iff a & m == b & m
 *
 * - mask m may have less than 5 bytes (rn->rn_masks do this)
 * - uses handcrafted keys to test key_isin in isolation
 *
 */

void
test_key_isin_simple(void)
{
   /*
    * Test simple matches
    */

    uint8_t a[IP4_KEYLEN], b[IP4_KEYLEN], m[IP4_KEYLEN];

    a[0] = b[0] = m[0] = 0x05;  /* LEN byte */
    a[1] = b[1] = m[1] = 0x00;
    a[2] = b[2] = m[2] = 0x00;
    a[3] = b[3] = m[3] = 0x00;
    a[4] = b[4] = m[4] = 0x00;

    // 0.0.0.0 is in 0.0.0.0/0
    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    // 255.255.255.255 is in 0.0.0.0/0, and
    // 0.0.0.0 is in 255.255.255.255/0
    a[1] = a[2] = a[3] = a[4] = 0xff;

    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    // 255.255.255.255 is NOT in 0.0.0.0/1
    // 0.0.0.0 is NOT in 255.255.255.255/1
    a[1] = a[2] = a[3] = a[4] = 0xff;
    b[1] = b[2] = b[3] = b[4] = 0x00;
    m[1] = m[2] = m[3] = m[4] = 0x80;

    mu_false(key_isin(a, b, m));
    mu_false(key_isin(b, a, m));

    // 255.255.255.255 is in 255.255.255.255/32
    a[1] = a[2] = a[3] = a[4] = 0xff;
    b[1] = b[2] = b[3] = b[4] = 0xff;
    m[1] = m[2] = m[3] = m[4] = 0xff;

    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    // 1.2.3.4 isin 1.2.3.4/32
    a[1] = b[1] = 0x01;
    a[2] = b[2] = 0x02;
    a[3] = b[3] = 0x03;
    a[4] = b[4] = 0x04;
    m[1] = m[2] = m[3] = m[4] = 0xff;

    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    // 1.2.3.4 is NOT in 1.2.3.3/30
    a[1] = b[1] = 0x01;
    a[2] = b[2] = 0x02;
    a[3] = b[3] = 0x03;
    a[4] = 0x04; b[4] = 0x03;
    m[1] = m[2] = m[3] = 0xff;
    m[4] = 0xfd;

    mu_false(key_isin(a, b, m));
    mu_false(key_isin(b, a, m));

    // 1.2.3.0 is in 1.2.3.0/31
    // 1.2.3.1 is in 1.2.3.0/31
    // 1.2.3.2 is NOT in 1.2.3.0/31
    a[1] = b[1] = 0x01;
    a[2] = b[2] = 0x02;
    a[3] = b[3] = 0x03;
    a[4] = 0x00; b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xff;
    m[4] = 0xfe;
    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    a[1] = 0x01;
    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));

    a[1] = 0x02;
    mu_false(key_isin(a, b, m));
    mu_false(key_isin(b, a, m));

    // 10.10.10.0 is NOT in 0.0.0.0/24
    a[1] = a[2] = a[3] = a[4] = 0x0a;
    b[1] = b[2] = b[3] = b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xff; m[4] = 0x00;

    mu_false(key_isin(a, b, m));
    mu_false(key_isin(b, a, m));

}
void
test_key_isin_lenbyte(void)
{
  /*
   * test LEN byte behaviour
   */

    uint8_t a[IP4_KEYLEN], b[IP4_KEYLEN], m[IP4_KEYLEN];

    a[0] = 0x00; b[0] = m[0] = 0x05;  /* LEN byte */

    /* 1.1.1.1 (LEN=0) is NOT in 1.1.1.1/24 */
    a[1] = a[2] = a[3] = a[4] = 0x01;
    b[1] = b[2] = b[3] = b[4] = 0x01;
    m[1] = m[2] = m[3] = 0xff; m[4] = 0x00;

    // a has LEN=0, so it will match anything
    mu_true(key_isin(a, b, m));
    mu_true(key_isin(b, a, m));
}

void
test_key_isin_masks(void)
{
    uint8_t a[IP4_KEYLEN], b[IP4_KEYLEN], m[IP4_KEYLEN];

    a[0] = b[0] = m[0] = 0x05;  /* LEN byte */
    a[1] = b[1] = 0x01;
    a[2] = b[2] = 0x02;
    a[3] = 0x03; b[3] = 0x05;
    a[4] = 0x00; b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xff;
    m[4] = 0x00;
    /* a = 1.2.3.0, b = 1.2.5.0, m = 255.255.255.0 */
    mu_false(key_isin(a, b, m));
    mu_false(key_isin(b, a, m));
}
