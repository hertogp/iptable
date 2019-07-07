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
#include "test_c_tbl_less.h"

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

// Tests

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

void
test_tbl_less_good(void)
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
    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // walkabout and sum the values associated with all prefixes

    // less than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    include = 1; // include /32 won't change anything, it's not in iptable
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    // 11.x.y.z crosscheck, should find 0/0 & 4 * an 11.10.10.x/y prefix
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "11.10.10.129", include, cb_sum, total));
    mu_eq(1+16+16+16+16, *total, "%d");

    // less than /25
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/25", include, cb_sum, total));
    mu_eq(1+2+4+8+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/25", include, cb_sum, total));
    mu_eq(1+2+4+8+16, *total, "%d");

    // less than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(1+2+4+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/24", include, cb_sum, total));
    mu_eq(1+2+4+8+0, *total, "%d");

    // less than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(1+2+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/16", include, cb_sum, total));
    mu_eq(1+2+4+0+0, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(1+0+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/8", include, cb_sum, total));
    mu_eq(1+2+0+0+0, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(0+0+0+0+0, *total, "%d");

    include = 1; // now include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.128/0", include, cb_sum, total));
    mu_eq(1+0+0+0+0, *total, "%d");

    tbl_destroy(&ipt, NULL);
}

int cb_count(struct radix_node *rn, void *runtotal);
int
cb_count(struct radix_node *rn, void *runtotal)
{
    // return 0 on success, else walktree will quit walking
    // cb_count assumes both runtotal and entry->value are (int *)
    // `-> counts the number of times cb_count is called

    if (rn == NULL || runtotal == NULL) return 1; // breaks off the walkabout

    *(int *)runtotal += 1;

    return 0;
}

void
test_tbl_less_traversal(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    // Check how many times the callback is called
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
    snprintf(pfx, MAX_STRKEY, "11.0.0.0/8");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.0.0/16");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.0/24");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    snprintf(pfx, MAX_STRKEY, "10.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));
    snprintf(pfx, MAX_STRKEY, "11.10.10.128/25");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    mu_assert(9 == ipt->count4);

    // walkabout and count the num of times the callback is called

    // less than /32
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_count, total));
    mu_eq(5, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129", include, cb_count, total));
    mu_eq(5, *total, "%d");

    // less than /25
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/25", include, cb_count, total));
    mu_eq(4, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/25", include, cb_count, total));
    mu_eq(5, *total, "%d");

    // less than /24
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/24", include, cb_count, total));
    mu_eq(3, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/24", include, cb_count, total));
    mu_eq(4, *total, "%d");

    // less than /16
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/16", include, cb_count, total));
    mu_eq(2, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/16", include, cb_count, total));
    mu_eq(3, *total, "%d");

    // less than /8
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/8", include, cb_count, total));
    mu_eq(1, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/8", include, cb_count, total));
    mu_eq(2, *total, "%d");

    // less than /0
    include = 0; // don't include search pfx in results
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/0", include, cb_count, total));
    mu_eq(0, *total, "%d");

    include = 1; // won't change anything, since the /32 is not in the tree
    *total = 0;
    mu_assert(tbl_less(ipt, "10.10.10.129/0", include, cb_count, total));
    mu_eq(1, *total, "%d");

    tbl_destroy(&ipt, NULL);
}
