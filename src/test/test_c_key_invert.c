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
#include "test_c_key_invert.h"

/*
 * key_invert(void *k)
 *
 * Inverts key k.  Respects LEN-byte.
 *
 */

void
test_invert_null(void)
{
    /* fails on NULL ptr */

    mu_false(key_invert(NULL));
}

void
test_invert_zerokey(void)
{
    /* fails on absence of key */

    uint8_t key[1] = {0};  /* no byte array LEN, no key bits */

    mu_false(key_invert(key));
    mu_eq(0, key[0], "LEN-byte %u");

}

void
test_invert_no_keybits(void)
{
    /* fails on absence of key bits */

    uint8_t key[1] = {1};  /* byte array w/ LEN (1), no key bits */

    mu_false(key_invert(key));
    mu_eq(1, key[0], "LEN-byte %u");
}

void
test_invert_len(void)
{
    uint8_t key[5] = {3, 0, 0, 0, 0};

    /* honors LEN byte */

    mu_true(key_invert(key));
    mu_eq(0x03, key[0], "key[0] %u");
    mu_eq(0xff, key[1], "key[1] %u");
    mu_eq(0xff, key[2], "key[2] %u");
    mu_eq(0x00, key[3], "key[3] %u");
    mu_eq(0x00, key[4], "key[4] %u");
}

void
test_invert_roundtrip(void)
{
    uint8_t key[MAX_BINKEY] = {0};

    /* inverting a key twice should yield the original key again.
     *
     * So for various LEN's a key is created [LEN, 1, 2, .. LEN-1], which
     * is then inverted twice and the result is checked against the original
     * calculated key.
     *
     * LEN starts at 2 to have at least 1 valid key-byte.
     *
     */

    for (int LEN = 2; LEN < MAX_BINKEY; LEN++) {
        key[0] = LEN;
        for (int i = 1; i < LEN; i++)
            key[i] = i;

        mu_true(key_invert(key));
        mu_true(key_invert(key));

        int success = 1;
        for (int i = 1; i < LEN; i++)
            success &= (key[i] == i);

        mu_eq(1, success, "roundtrip success is %d");
    }
}
