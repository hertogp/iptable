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
#include "test_c_key_bypair.h"    // a generated header file for this test runner

/*
 * key_bypair(a, b, m)
 */

void
test_key_bypair_simple(void)
{
   /*
    * Test simple matches
    */

    uint8_t a[MAX_BINKEY] = {0}, b[MAX_BINKEY] = {0}, m[MAX_BINKEY]={0};
    uint8_t *p;

    b[0] = m[0] = 0x05;                         /* LEN byte */

    /* pair key for 1.1.1.128/25 is 1.1.1.0 */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0x80;
    m[1] = m[2] = m[3] = 0xFF; m[4] = 0x80;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == b[2]);
    mu_true(a[3] == b[3]);
    mu_true(a[4] == 0);


    /* pair key for 1.1.1.0/25 is 1.1.1.128 */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xFF; m[4] = 0x80;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == b[2]);
    mu_true(a[3] == b[3]);
    mu_true(a[4] == 0x80);


    /* pair key for 1.1.1.0/24 is 1.1.0.0 */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xFF; m[4] = 0x00;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == b[2]);
    mu_true(a[3] == 0x00);
    mu_true(a[4] == 0x00);


    /* pair key for 10.10.0.0/16 is 10.11.0.0 */
    b[1] = b[2] = 0x0a; b[3] = b[4] = 0x00;
    m[1] = m[2] = 0xFF; m[3] = m[4] = 0x00;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == 0x0b);
    mu_true(a[3] == 0x00);
    mu_true(a[4] == 0x00);

    /* pair key for 10.10.10.12/30 is 10.10.10.8/30 */
    b[1] = b[2] = b[3] = 0x0a; b[4] = 0x0c;
    m[1] = m[2] = m[3] = 0xFF; m[4] = 0xfc;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == b[2]);
    mu_true(a[3] == b[3]);
    mu_true(a[4] == 0x08);
}

void
test_key_bypair_lenbyte(void)
{
   /*
    * The pair key has as many bytes as the key its paired with
    */

    uint8_t a[MAX_BINKEY], b[MAX_BINKEY] = {0}, m[MAX_BINKEY]={0};
    uint8_t *p;

    b[0] = 0x05;            /* LEN byte */
    m[0] = 0x03;            /* LEN byte is 3 for [LEN,0xFF,0xFF,0,..]  mask */

    /* pair key for 1.3.0.0/16 is 1.2.0.0 both fit into 1.2.0.0/15 */
    b[1] = 0x01; b[2] = 0x03; b[3] = b[4] = 0x00;
    m[1] = m[2] = 0xFF;

    p = key_bypair(a, b , m);
    mu_true(p);
    mu_true(a[0] == b[0]);  /* LEN byte is copied over */
    mu_true(a[1] == b[1]);
    mu_true(a[2] == 0x02);
    mu_true(a[3] == 0x00);
    mu_true(a[4] == 0x00);
}

void
test_key_bypair_nulls(void)
{
   /*
    * key_bypair should hanlde erronuous input
    */

    uint8_t a[MAX_BINKEY], b[MAX_BINKEY] = {0}, m[MAX_BINKEY]={0};

    b[0] = 0x05;            /* LEN byte */
    m[0] = 0x05;            /* LEN byte is 3 for [LEN,0xFF,0xFF,0,..]  mask */

    /* src key is 1.1.1.0/24 */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0x00;
    m[1] = m[2] = m[3] = 0xFF; m[4] = 0x00;

    mu_false(key_bypair(NULL, b , m));
    mu_false(key_bypair(a, NULL, m));
    mu_false(key_bypair(a, b , NULL));
    mu_false(key_bypair(a, b , NULL));

    /* zero length address */
    b[0] = 0;
    mu_false(key_bypair(a, b , m));
    b[0] = 0x05;
    /* zero length mask */
    m[0] = 0x00;
    mu_false(key_bypair(a, b , m));
}

void
test_key_bypair_hosts(void)
{
   /*
    * key_bypair should hanlde erronuous input
    */

    uint8_t a[MAX_BINKEY], b[MAX_BINKEY] = {0}, m[MAX_BINKEY]={0};

    b[0] = 0x05;            /* LEN byte */
    m[0] = 0x05;            /* LEN byte is 3 for [LEN,0xFF,0xFF,0,..]  mask */

    /* pair key for 1.1.1.255/32 is 1.1.1.254 */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0xff;
    m[1] = m[2] = m[3] = m[4] = 0xFF;

    mu_true(key_bypair(a, b, m));
    mu_true(a[0] == b[0]);
    mu_true(a[1] == b[1]);
    mu_true(a[2] == b[2]);
    mu_true(a[3] == b[3]);
    mu_true(a[4] == 0xfe);
}

void
test_key_bypair_zeromask(void)
{
   /*
    * key_bypair should hanlde erronuous input
    */

    uint8_t a[MAX_BINKEY], b[MAX_BINKEY] = {0}, m[MAX_BINKEY]={0};

    b[0] = 0x05;            /* LEN byte */
    m[0] = 0x05;            /* LEN byte is 3 for [LEN,0xFF,0xFF,0,..]  mask */

    /* pair key for 1.1.1.255/0 is ...? */
    b[1] = b[2] = b[3] = 0x01; b[4] = 0xff;
    m[1] = m[2] = m[3] = m[4] = 0x00;

    mu_false(key_bypair(a, b, m));
}
