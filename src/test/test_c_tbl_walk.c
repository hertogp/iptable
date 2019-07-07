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
#include "test_c_tbl_walk.h"

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
test_tbl_walk_good(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction
    char pfx[MAX_STRKEY];
    int number[5] = {1, 2, 4, 8, 16};
    int total[1] = {0};
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    // add a few prefixes

    snprintf(pfx, MAX_STRKEY, "0.0.0.0/0");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));

    snprintf(pfx, MAX_STRKEY, "1.1.1.1/8");
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));

    snprintf(pfx, MAX_STRKEY, "2.2.2.2/16");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    snprintf(pfx, MAX_STRKEY, "3.3.3.3/24");
    mu_assert(tbl_set(ipt, pfx, number+3, NULL));

    snprintf(pfx, MAX_STRKEY, "4.4.4.4/32");
    mu_assert(tbl_set(ipt, pfx, number+4, NULL));

    // we should have 5 prefixes
    mu_assert(5 == ipt->count4);

    // walkabout and sum the values associated with all prefixes
    mu_assert(tbl_walk(ipt, cb_sum, total));
    mu_assert(1+2+4+8+16 == *total);

    tbl_destroy(&ipt, NULL);

    return;
}
