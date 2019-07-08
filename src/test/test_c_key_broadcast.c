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
#include "test_c_key_broadcast.h"

/*
 * int key_broadcast(void *key, void *mask);
 *
 * Turns key into broadcast address for given key and mask.
 * Returns 1 on success, or 0 on failure.
 *
 */

void
test_bcast_null(void)
{
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];

    /* handles NULL ptrs by failing */

    mu_false(key_broadcast(NULL, NULL));
    mu_false(key_broadcast(addr, NULL));
    mu_false(key_broadcast(NULL, mask));
}

/*
 * A key with length zero has no broadcast address.
 *
 * key_broadcast() should fail and leave key untouched.
 *
 */

void
test_bcast_zeros(void)
{
    uint8_t addr[MAX_BINKEY] = {0}; /* all zeros */
    uint8_t mask[MAX_BINKEY] = {0}; /* all zeros */

    for (int i = 1; i < MAX_BINKEY; i++)

    mu_false(key_broadcast(addr, mask));
    int bytesum = 0;
    for (int i = 0; i < MAX_BINKEY; i++) {
        bytesum += addr[i];
    }

    /* key not changed */
    mu_eq(0, bytesum, "summ(addr-bytes)= (%d)");
}

void
test_bcast_nokey(void)
{
    uint8_t addr[MAX_BINKEY] = {1}; /* all zeros */
    uint8_t mask[MAX_BINKEY] = {0}; /* all zeros */

    mu_false(key_broadcast(addr, mask));
}

/*
 * A mask of length zero will result in all-ones for valid key bytes.
 *
 * - an addr LEN-byte==x, means (x-1) addr bytes.
 * - a mask of all zeros -> (x-1) addr bytes to be set to all-ones.
 *
 * Test all valid keylengths: 1 - MAX_BINKEY-1
 */

void
test_bcast_zeromask(void)
{

    uint8_t addr[MAX_BINKEY] = {5};  /* rest is all 0's */
    uint8_t mask[MAX_BINKEY] = {0};  /* mask is all 0's */
    int allones = 0;

    /* start addr len at 2, to have actual key bits */
    for(uint8_t LEN = 2; LEN < MAX_BINKEY; LEN++) {
        addr[0] = LEN;

        mu_true(key_broadcast(addr, mask));

        allones = 0;
        for (int j = 1; j < MAX_BINKEY; j++) {
            allones = addr[j] == 0xff ? allones+1 : allones+0;
        }
        /* i is addr LEN-byte => i-1 is the num of actual addr bytes */
        mu_eq(LEN-1, allones, "num-allones (%d)");
    }
}

/*
 * A mask of proper length & actual mask of zeros results in addr all-ones.
 *
 * - an addr LEN-byte==x, means (x-1) addr bytes.
 * - a mask of all zeros -> (x-1) addr bytes to be set to all-ones.
 *
 * Test all valid keylengths: 1 - MAX_BINKEY-1
 */

void
test_bcast_properzeromask(void)
{

    uint8_t addr[MAX_BINKEY] = {0};  /* all 0's */
    uint8_t mask[MAX_BINKEY] = {0};  /* all 0's, for now */
    int allones = 0;

    /* start addr len at 2, the first legal LEN value */
    for(uint8_t LEN = 2; LEN < MAX_BINKEY; LEN++) {
        addr[0] = mask[0] = LEN;

        mu_true(key_broadcast(addr, mask));

        allones = 0;
        for (int j = 1; j < MAX_BINKEY; j++) {
            allones = addr[j] == 0xff ? allones+1 : allones+0;
        }
        /* i is addr LEN-byte => i-1 is the num of actual addr bytes */
        mu_eq(LEN-1, allones, "num-allones (%d)");
    }
}

/*
 * A host address (whose mask is all-ones) has itself as broadcast address.
 *
 */

void
test_bcast_zeroaddr_onesmask(void)
{

    uint8_t addr[MAX_BINKEY] = {0};
    uint8_t mask[MAX_BINKEY] = {0};
    int nonzero = 0;

    /* set all mask bytes to all-ones */
    for(int i = 1; i < MAX_BINKEY; i++)
        mask[i] = 0xff;

    /* test different legal addr LEN's, set mask to fit its length */
    for(uint8_t LEN = 2; LEN < MAX_BINKEY; LEN++) {
        addr[0] = mask[0] = LEN;

        mu_true(key_broadcast(addr, mask));

        /* addr bytes should still all be zero */
        nonzero = 0;
        for (int j = 1; j < MAX_BINKEY; j++) {
            nonzero += addr[j];
        }

        mu_eq(0, nonzero, "nonzer addr bytes (%d)");
    }
}

/*
 * broadcast() must handle illegal LEN's
 *
 */

void
test_bcast_masktoobig_1(void)
{

    uint8_t addr[MAX_BINKEY] = {0};
    uint8_t mask[MAX_BINKEY] = {MAX_BINKEY+1};

    mu_false(key_broadcast(addr, mask));

}

/*
 * broadcast() refuses to apply bigger mask to smaller addr
 *
 */

void
test_bcast_masktoobig_2(void)
{

    uint8_t addr[MAX_BINKEY] = {2, 0xff};
    uint8_t mask[MAX_BINKEY] = {255, 0xff};

    mu_false(key_broadcast(addr, mask));

    mask[0] = MAX_BINKEY;
    mu_false(key_broadcast(addr, mask));

}

void
test_bcast_charbufs(void)
{

    char addr[MAX_BINKEY] = {2, -1};
    char mask[MAX_BINKEY] = {-1, -1};

    mu_false(key_broadcast(addr, mask));

    mask[0] = MAX_BINKEY;
    mu_false(key_broadcast(addr, mask));

}

/* some known good tests */

void
test_bcast_noncontiguous(void)
{
    /* non-contiguous masks, unusual but allowed */
    uint8_t addr[MAX_BINKEY] = {7, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f};
    uint8_t mask[MAX_BINKEY] = {7, 0x10, 0x20, 0x3f, 0x4f, 0x00, 0xf0};

    mu_true(key_broadcast(addr, mask));

    mu_eq(7, addr[0], "LEN %u");
    mu_eq(0xff, addr[1], "addr[1] %u");  /* a := a | ~m */
    mu_eq(0xff, addr[2], "addr[2] %u");
    mu_eq(0xfc, addr[3], "addr[3] %u");
    mu_eq(0xfd, addr[4], "addr[4] %u");
    mu_eq(0xff, addr[5], "addr[5] %u");
    mu_eq(0x6f, addr[6], "addr[6] %u");
}


void
test_bcast_good_01(void)
{
    uint8_t addr[MAX_BINKEY] = {2, 0x80};
    uint8_t mask[MAX_BINKEY] = {2, 0xf0};

    mu_true(key_broadcast(addr, mask));
    mu_eq(0x02, addr[0], "len-byte %u");
    mu_eq(0x8f, addr[1], "addr[1] %u");
}

void
test_bcast_good_02(void)
{
    uint8_t addr[MAX_BINKEY] = {3, 0xf0, 0xf0};
    uint8_t mask[MAX_BINKEY] = {3, 0xff, 0xf0};

    mu_true(key_broadcast(addr, mask));

    mu_eq(0x03, addr[0], "len-byte %u");
    mu_eq(0xf0, addr[1], "addr[1] %u");
    mu_eq(0xff, addr[2], "addr[2] %u");
}

void
test_bcast_good_03(void)
{
    uint8_t addr[MAX_BINKEY] = {5, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t mask[MAX_BINKEY] = {5, 0xff, 0xff, 0x00, 0x00};

    mu_true(key_broadcast(addr, mask));

    /* addr is 10.10.255.255 */
    mu_eq(0x05, addr[0], "len-byte %u");
    mu_eq(0x0a, addr[1], "addr[1] %u");
    mu_eq(0x0a, addr[2], "addr[2] %u");
    mu_eq(0xff, addr[3], "addr[3] %u");
    mu_eq(0xff, addr[4], "addr[4] %u");

    /* missing mask bytes are assumed to be 0x00 */
    addr[1] = addr[2] = addr[3] = addr[4] = 0x0a;
    mask[0] = 3;

    mu_true(key_broadcast(addr, mask));

    /* addr is 10.10.255.255 */
    mu_eq(0x05, addr[0], "len-byte %u");
    mu_eq(0x0a, addr[1], "addr[1] %u");
    mu_eq(0x0a, addr[2], "addr[2] %u");
    mu_eq(0xff, addr[3], "addr[3] %u");
    mu_eq(0xff, addr[4], "addr[4] %u");
}
