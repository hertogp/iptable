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
#include "test_c_rdx_pairleaf.h"

typedef struct testpfx_t {
    const char *pfx;
    int  dta;
} testpfx_t;

/*
 * INT_VALUE provides easy access to an entry_t's integer value
 * SIZE_T casts an int to size_t to matchup with ipt->count{4,6} values
 *
 */

#define VALUE(x) (*(int *)(((entry_t *)x)->value))
#define SIZE_T(x) ((size_t)x)
#define NELEMS(x) (int)(sizeof(x) / sizeof(x[0]))

void
test_emptytable(void)
{

    /* check pairleaf for an empty table */

    table_t *t = tbl_create(NULL);
    struct radix_node *rn;

    rn = rdx_firstleaf(&t->head4->rh);
    rn = rdx_pairleaf(rn);
    mu_eq(NULL, (void *)rn, "%p");
    tbl_destroy(&t, NULL);
}

void
test_nulls(void)
{
    mu_false(rdx_pairleaf(NULL));
}

void
test_host0(void)
{
    /* check pairleaf for 0.0.0.0/32 */
    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
        {"0.0.0.0/32", 1},
        {"0.0.0.1/32", 2},
    };
    struct radix_node *rn, *pair;

    /* insert only 0.0.0.0/32, no pairleaf to be found */
    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    rn = rdx_firstleaf(&t->head4->rh);
    mu_eq((void *)t->head4->rnh_nodes[0].rn_dupedkey, (void *)rn, "%p");
    pair = rdx_pairleaf(rn);
    mu_eq(NULL, (void *)pair, "%p");

    /* insert 0.0.0.1/32, the pair-key for 0.0.0.0/32 */
    mu_assert(tbl_set(t, pfx[1].pfx, &pfx[1].dta, NULL));
    pair = rdx_pairleaf(rn);
    mu_true(pair);
    if (pair)
        mu_eq(2, VALUE(pair), "%d");
    else
        mu_failed("unexpected pair %p\n", (void *)pair);

    tbl_destroy(&t, NULL);
}

void
test_host255(void)
{
    /* check pairleaf for 0.0.0.0/32 */
    table_t *t = tbl_create(NULL);
    entry_t *e;
    testpfx_t pfx[] = {
        {"255.255.255.255/32", 1},
        {"255.255.255.254/32", 2},
    };
    struct radix_node *pair;

    for(int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    e = tbl_get(t, pfx[0].pfx);
    if(e) {
        mu_eq(pfx[0].dta, VALUE(e), "%d");
        pair = rdx_pairleaf(&e->rn[0]);
        mu_true(pair);
        if (pair) mu_eq(pfx[1].dta, VALUE(pair), "%d");
        else mu_failed("expected value %d", pfx[1].dta);
    } else
        mu_failed("could not find %s!", pfx[0].pfx);

    /* and vice versa */
    e = tbl_get(t, pfx[1].pfx);
    if(e) {
        mu_eq(pfx[1].dta, VALUE(e), "%d");
        pair = rdx_pairleaf(&e->rn[0]);
        mu_true(pair);
        if (pair) mu_eq(pfx[0].dta, VALUE(pair), "%d");
        else mu_failed("expected value %d", pfx[0].dta);

    } else
        mu_failed("could not find %s!", pfx[1].pfx);


        tbl_destroy(&t, NULL);
}



void
test_somepairs(void)
{
    /* check we reach all left-end marker's dupedkeys if its has multiple */
    table_t *t = tbl_create(NULL);
    entry_t *e;
    testpfx_t pfx[] = {
        {"192.168.1.0/24",    1},
        /* pairs of prefixes below */
        {"192.168.1.0/25",    2},
        {"192.168.1.128/25",  4},
        {"192.168.1.0/26",    8},
        {"192.168.1.64/26",  16},
        {"192.168.1.128/26", 32},
        {"192.168.1.192/26", 64},
    };
    struct radix_node *pair;

    for(int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    e = tbl_get(t, pfx[0].pfx);
    mu_eq(1, VALUE(e), "%d");
    pair = rdx_pairleaf(e->rn);
    mu_false(pair);     /* since 192.168.0.0/24 isn't present */

    for (int i = 1; i < 6; i+=2) {
        e = tbl_get(t, pfx[i].pfx);
        mu_eq(pfx[i].dta, VALUE(e), "%d");
        pair = rdx_pairleaf(&e->rn[0]);
        mu_true(pair);
        if (pair) mu_eq(pfx[i+1].dta, VALUE(pair), "%d");
        else mu_failed("expected value %d", pfx[i+1].dta);

        /* and vice versa */
        e = tbl_get(t, pfx[i+1].pfx);
        mu_eq(pfx[i+1].dta, VALUE(e), "%d");
        pair = rdx_pairleaf(&e->rn[0]);
        mu_true(pair);
        if (pair) mu_eq(pfx[i].dta, VALUE(pair), "%d");
        else mu_failed("expected value %d", pfx[i].dta);
    }

    tbl_destroy(&t, NULL);
}

