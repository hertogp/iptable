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
#include "test_c_rdx_nextleaf.h"

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

    /* check we donot yield the root-leafs for an empty table */

    table_t *t = tbl_create(NULL);
    struct radix_node *rn;

    rn = rdx_firstleaf(&t->head4->rh);
    rn = rdx_nextleaf(rn);
    mu_eq(NULL, (void *)rn, "%p");
    tbl_destroy(&t, NULL);
}

void
test_host0(void)
{
    /* check we reach left-end marker's dupedkey if its the only entry */
    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = { {"0.0.0.0/32", 1} };
    struct radix_node *rn;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    rn = rdx_firstleaf(&t->head4->rh);
    mu_eq((void *)t->head4->rnh_nodes[0].rn_dupedkey, (void *)rn, "%p");
    rn = rdx_nextleaf(rn);
    mu_eq(NULL, (void *)rn, "%p");

    tbl_destroy(&t, NULL);
}

void
test_nxhost0(void)
{
    /* check we reach all left-end marker's dupedkeys if its has multiple */
    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
        {"0.0.0.0/32", 1},
        {"0.0.0.0/24", 1},
        {"0.0.0.0/16", 1},
        {"0.0.0.0/8",  1},
        {"0.0.0.0/1",  1},
        {"0.0.0.0/0",  1},
    };
    struct radix_node *rn;
    int cnt = 0;

    for(int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    cnt = 0;
    rn = rdx_firstleaf(&t->head4->rh);
    if(rn)
        cnt += 1;

    while((rn = rdx_nextleaf(rn)))
        cnt += 1;
    mu_eq(NELEMS(pfx), cnt, "%d");

    tbl_destroy(&t, NULL);
}

void
test_host128(void)
{
    /* check we reach a single, normal leaf */

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
    } else {
        mu_failed("host128 not found, got %p", (void *)rn);
    }
    rn = rdx_nextleaf(rn);
    mu_eq(NULL, (void *)rn, "%p");

    tbl_destroy(&t, NULL);
}

void
test_endmarker(void)
{
    /* check we reach right-end marker's dupedkey if its the only entry */

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = { {"255.255.255.255/32", 1} };
    struct radix_node *rn;

    mu_assert(tbl_set(t, pfx[0].pfx, &pfx[0].dta, NULL));
    rn = rdx_firstleaf(&t->head4->rh);
    rn = rdx_nextleaf(rn);
    mu_eq(NULL, (void *)rn, "%p");

    tbl_destroy(&t, NULL);
}

void
test_endmarkers(void)
{
    /* check we also reach right-end marker's dupedkey, in the face of
     * some more table entries */

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
      {"255.255.255.255/32", 1},
      {"255.255.255.255/24", 1},
      {"255.255.255.255/16", 1},
    };
    struct radix_node *rn;
    int count = 0;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);
    count = 1;
    while ( (rn = rdx_nextleaf(rn)) )
      count += 1;

    mu_eq(NELEMS(pfx), count, "count endmarkers %d");

    tbl_destroy(&t, NULL);
}

void
test_left_right_leafs(void)
{
    /* check we also reach right-end marker's dupedkey, in the face of
     * some more table entries */

    table_t *t = tbl_create(NULL);
    testpfx_t pfx[] = {
      {"0.0.0.0/1", 1},
      {"0.0.0.0/24", 1},
      {"0.0.0.0", 1},
      {"192.1.1.1", 1},
      {"192.1.1.3", 1},
      {"128.1.1.1", 1},
      {"128.1.1.2", 1},
      {"255.255.255.255/32", 1},
    };
    struct radix_node *rn;
    int count = 0;

    for (int i = 0; i < NELEMS(pfx); i++)
        mu_assert(tbl_set(t, pfx[i].pfx, &pfx[i].dta, NULL));

    rn = rdx_firstleaf(&t->head4->rh);
    mu_assert(rn);
    count = 1;
    while ( (rn = rdx_nextleaf(rn)) )
      count += 1;

    mu_eq(NELEMS(pfx), count, "count all leafs %d");

    tbl_destroy(&t, NULL);
}
