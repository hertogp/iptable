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
#include "test_c_tbl_more.h"    // a generated header file for this test runner

/*
 * Test cases
 *
 * Tests store references to local numbers on the stack and thus use:
 *   t = tbl_create(NULL)           - no purge function needed
 *   tbl_set(t, pfx, &number, NULL) - and no purge args needed.
 * to create an iptable t & fill it with prefixes.
 */

typedef struct testpfx_t {
    const char *pfx;
    int dta;
} testpfx_t;

/*
 * INT_VALUE provides easy access to an entry_t's integer value
 * SIZE_T casts an int to size_t to matchup with ipt->count{4,6} values
 */

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)(x))


int cb_sum(struct radix_node *rn, void *runtotal);
int
cb_sum(struct radix_node *rn, void *runtotal)
{
    // return 0 on success, else walktree will quit walking
    // cb_sum assumes both runtotal and entry->value are (int *)

    if (rn == NULL || runtotal == NULL) return 1; // breaks off the walkabout

    entry_t *itm = (entry_t *)rn;
    *(int *)runtotal += *(int *)itm->value;

    return 0;
}

// Tests

void
test_tbl_more_good(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));
    snprintf(pfx, MAX_STRKEY, "10.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "10.10.10.128/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // more than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128", include, cb_sum, total));
    mu_eq(0+0+0+0+0, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128", include, cb_sum, total));
    mu_eq(0+0+0+0+16, *total, "%d");

    // more than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(0+0+0+0+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(0+0+0+8+16, *total, "%d");

    // more than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(0+0+0+8+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(0+0+4+8+16, *total, "%d");

    // more than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(0+0+4+8+16, *total, "%d");

    include = 1; // this time include search key (host ip) i/t results
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(0+2+4+8+16, *total, "%d");

    // more than /0
    include = 0; // anything more specific than /0, means all pfx's but 0/0
    *total = 0;  // so all 4 11.x.y.z/m (4*16) and all 10.x.y.z/m (1+2+4+8+16)
    mu_assert(tbl_more(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(0+2+4+8+16+4*16, *total, "%d");

    include = 1; // this time include 0/0 as well
    *total = 0;
    mu_assert(tbl_more(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(1+2+4+8+16+4*16, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_more_again(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[7] = {1, 2, 4, 8, 16, 32, 64};
    int total[1] = {0}, include = 0;
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/24");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/25");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.128/25");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.0/26");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.64/26");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.128/26");
    mu_assert(tbl_set(ipt, pfx, number+5, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.192/26");
    mu_assert(tbl_set(ipt, pfx, number+6, NULL));

    mu_assert(7 == ipt->count4);

    // more than /24
    include = 0; // search pfx /24 is excluded
    *total = 0;
    mu_assert(tbl_more(ipt, "1.1.1.0/24", include, cb_sum, total));
    mu_eq(0+2+4+8+16+32+64, *total, "%d");

    tbl_destroy(&ipt, NULL);
}
