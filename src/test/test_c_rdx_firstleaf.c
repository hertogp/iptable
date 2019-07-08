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

#include "minunit.h"          // the mu_test macros
#include "test_c_rdx_firstleaf.h"

typedef struct testpfx_t {
    const char *pfx;
    int  dta;
} testpfx_t;

/*
 * INT_VALUE provides easy access to an entry_t's integer value
 * SIZE_T casts an int to size_t to matchup with ipt->count{4,6} values
 *
 */

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)x)
#define NELEMS(x) (int)(sizeof(x) / sizeof(x[0]))

void
test_emptytable(void)
{

    table_t *t = tbl_create(NULL);
    struct radix_node *rn;

    rn = rdx_firstleaf(&t->head4->rh);
    mu_eq(NULL, (void *)rn, "%p");
    tbl_destroy(&t, NULL);
}

void
test_host0(void)
{

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = { {"0.0.0.0/32", 1} };
    struct radix_node *rn;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    rn = rdx_firstleaf(&t->head4->rh);
    mu_eq((void *)t->head4->rnh_nodes[0].rn_dupedkey, (void *)rn, "%p");

    tbl_destroy(&t, NULL);
}

void
test_host128(void)
{

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = { {"128.128.128.128/32", 1} };
    struct radix_node *rn;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);
    if(rn) {
        mu_eq(0x05, 0xFF & *(rn->rn_key+0), "LEN byte 0x%02x");
        mu_eq( 128, 0xFF & *(rn->rn_key+1), "LEN byte 0x%02x");
        mu_eq( 128, 0xFF & *(rn->rn_key+2), "LEN byte 0x%02x");
        mu_eq( 128, 0xFF & *(rn->rn_key+3), "LEN byte 0x%02x");
        mu_eq( 128, 0xFF & *(rn->rn_key+4), "LEN byte 0x%02x");
    } else
        mu_failed("host128 not found, got %p", (void *)rn);

    tbl_destroy(&t, NULL);
}

/* host255:
 * - yields a memory leak?
 * - is not found by firstleaf
 */

void
test_host255(void)
{

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = { {"255.255.255.255/32", 1} };
    struct radix_node *rn;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_eq((void *)t->head4->rnh_nodes[2].rn_dupedkey, (void *)rn, "%p");

    tbl_destroy(&t, NULL);
}

void
test_twosubnets(void)
{

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
        {"10.10.10.10/24", 1},
        {"11.11.11.11/24", 1},
    };
    struct radix_node *rn;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);

    tbl_destroy(&t, NULL);
}

void
test_threemin(void)
{
    /* 0-key with a mask and 2 normal subnets */
    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
        {"0.0.0.0", 1},
        {"10.10.10.10/24", 1},
        {"11.11.11.11/24", 1},
    };
    struct radix_node *rn;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);

    tbl_destroy(&t, NULL);
}

void
test_threemax(void)
{
    /* 255-key with two normal subnets */
    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
        {"255.255.255.255", 1},
        {"10.10.10.10/24", 1},
        {"11.11.11.11/24", 1},
    };
    struct radix_node *rn;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);

    tbl_destroy(&t, NULL);
}
