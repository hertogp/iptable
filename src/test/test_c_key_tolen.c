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
#include "test_c_key_tolen.h"

void
test_key_tolen_good(void)
{
    int mlen;
    uint8_t *addr = malloc(5 * sizeof(uint8_t));

    // - all tests set *bytes*, so network byte order is ensured

    // set IPv4 addr keylen
    *addr = 1 + IP4_KEYLEN;

    // len 0
    *(addr+1) = 0x00;
    *(addr+2) = 0x00;
    *(addr+3) = 0x00;
    *(addr+4) = 0x00;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    // len 1
    *(addr+1) = 0x80;
    mlen = key_tolen(addr);
    mu_eq(1, mlen, "%i");

    // len 9
    *(addr+1) = 0xff;
    *(addr+2) = 0x80;
    mlen = key_tolen(addr);
    mu_eq(9, mlen, "%i");

    // len 16
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(16, mlen, "%i");

    // len 32
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(32, mlen, "%i");

    // count 1's from msb downto lsb?
    // len 32
    *(addr+1) = 0x00;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    // rn->mask may have LEN set to nr of non-zero bytes
    // in the array, which includes the LEN byte itself.
    // The tests below check this behaviour for key_tolen

    // count only the non-zero bytes?
    // LEN = 0 bytes
    *(addr+0) = 0x00;  // LEN=0 -> consider zero mask bytes (even LEN is 0)
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    // count only the non-zero bytes?
    // LEN = 1 byte
    *(addr+0) = 0x01;  // LEN=1 -> consider zero mask bytes (only LEN not 0)
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(0, mlen, "%i");

    // count only the non-zero bytes?
    // LEN = 2 bytes
    *(addr+0) = 0x02; // LEN=2 -> consider first mask byte only
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(8, mlen, "%i");

    // count only the non-zero bytes?
    // LEN = 2 bytes
    *(addr+0) = 0x03; // LEN=3 -> consider first two mask bytes
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(16, mlen, "%i");

    // count only the non-zero bytes?
    // LEN = 4 bytes
    *(addr+0) = 0x04; // LEN=4 -> consider first 3 mask bytes
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(24, mlen, "%i");

    // count only the non-zero bytes?
    // LEN = 5 bytes
    *(addr+0) = 0x05;  // LEN=5 -> consider first 4 mask bytes
    *(addr+1) = 0xff;
    *(addr+2) = 0xff;
    *(addr+3) = 0xff;
    *(addr+4) = 0xff;
    mlen = key_tolen(addr);
    mu_eq(32, mlen, "%i");

    free(addr);
}

void
test_key_tolen_bad(void)
{
    // NULL key
    int mlen = key_tolen(NULL);
    mu_eq(-1, mlen, "%i");
}
