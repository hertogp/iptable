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
#include "test_c_key_network.h"

/* int key_network(void *key, void *m)
 *
 * Turns key into network address for given key and mask.
 * Returns 1 on success, 0 on failure.
 *
 */

void
test_nwork_null(void)
{
    uint8_t addr[MAX_BINKEY] = {1, 0x1f};
    uint8_t mask[MAX_BINKEY] = {1, 0xf3};

    /* handles NULL pointers */

    mu_false(key_network(NULL, NULL));
    mu_false(key_network(NULL, mask));
    mu_false(key_network(addr, NULL));

    /* leaves addr, mask untouched */

    mu_eq(1, addr[0], "%u");
    mu_eq(0x1f, addr[1], "%u");

    mu_eq(1, mask[0], "%u");
    mu_eq(0xf3, mask[1], "%u");

}

void
test_nwork_zeros(void)
{
    uint8_t addr[MAX_BINKEY] = {0};
    uint8_t mask[MAX_BINKEY] = {2, 0xff};

    /* fails on addr with LEN 0: no network address possible */

    mu_false(key_network(addr, mask));
}

void
test_nwork_longermask(void)
{

    uint8_t addr[MAX_BINKEY] = {5,  0x1,  0x2,  0x3, 0x4};
    uint8_t mask[MAX_BINKEY] = {6, 0xff, 0xff, 0, 0,   0};

    /* fails if mask LEN is longer than addr's LEN */

    mu_false(key_network(addr, mask));

    /* leaves addr untouched */
    mu_eq(5, addr[0], "LEN %u");
    mu_eq(0x1, addr[1], "addr[1] %u");
    mu_eq(0x2, addr[2], "addr[1] %u");
    mu_eq(0x3, addr[3], "addr[1] %u");
    mu_eq(0x4, addr[4], "addr[1] %u");

}

void
test_nwork_shortermask(void)
{
    uint8_t addr[MAX_BINKEY] = {5, 0x1, 0x2, 0x3, 0x4};
    uint8_t mask[MAX_BINKEY] = {2, 0xff};

    /* assumes 0x0 for missing mask bytes if mask LEN is shorter */

    mu_true(key_network(addr, mask));

    mu_eq(5, addr[0], "LEN %u");
    mu_eq(0x1, addr[1], "addr[1] %u");
    mu_eq(0x0, addr[2], "addr[2] %u");
    mu_eq(0x0, addr[3], "addr[3] %u");
    mu_eq(0x0, addr[4], "addr[4] %u");
}

void
test_nwork_zerolenmask(void)
{
    uint8_t addr[MAX_BINKEY] = {MAX_BINKEY};
    uint8_t mask[MAX_BINKEY] = {0};

    /* a zero-length mask, turns addr into all zeros too */

    for(int i = 1; i < MAX_BINKEY; i++)
        addr[i] = i;

    mu_true(key_network(addr, mask));

    /* count num of all-zero address bytes */
    int zeros = 0;
    for (int i = 1; i < MAX_BINKEY; i++)
        zeros += (addr[i] == 0) ? 1 : 0;

    mu_eq(MAX_BINKEY, addr[0], "LEN %u");
    mu_eq(MAX_BINKEY-1, zeros, "num zero-bytes %d");
}

void
test_nwork_allzeromask(void)
{
    /* a full mask with all zeros also turns addr into all zeros */
    uint8_t addr[MAX_BINKEY] = {0};
    uint8_t mask[MAX_BINKEY] = {MAX_BINKEY};

    /* an all zero mask, turns addr into all zeros too */
    /* key := [MAX_BINKEY, 1, 2, .. MAX_BINKEY-1] */
    addr[0] = MAX_BINKEY;
    for(int i = 1; i < MAX_BINKEY; i++)
        addr[i] = i;

    /* a full, zeromask turns addr into all-zeros */

    mu_true(key_network(addr, mask));

    /* count num of all-zero address bytes */
    int zeros = 0;
    for (int i = 1; i < MAX_BINKEY; i++)
        if(addr[i] == 0)
            zeros += 1;

    mu_eq(MAX_BINKEY, addr[0], "LEN %u");
    mu_eq(MAX_BINKEY-1, zeros, "num zero-bytes %d");
}

void
test_nwork_noncontiguous(void)
{
    /* non-contiguous masks, unusual but allowed */
    uint8_t addr[MAX_BINKEY] = {7, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f};
    uint8_t mask[MAX_BINKEY] = {7, 0x10, 0x20, 0x3f, 0x4f, 0x00, 0xf0};

    mu_true(key_network(addr, mask));

    mu_eq(7, addr[0], "LEN %u");
    mu_eq(0x10, addr[1], "addr[1] %u");  /* a := a & m */
    mu_eq(0x20, addr[2], "addr[2] %u");
    mu_eq(0x3c, addr[3], "addr[3] %u");
    mu_eq(0x4d, addr[4], "addr[4] %u");
    mu_eq(0x00, addr[5], "addr[5] %u");
    mu_eq(0x60, addr[6], "addr[6] %u");
}

