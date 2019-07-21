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
#include "test_c_tbl_stack.h"

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)(x))

/*
 * Test tbl's stack for iterating across radix nodes of all types.
 *
 * Uses stack pop/push and rdx_first/nextnode
 *
 */

void
test_tbl_stackpush_pop(void)
{
    // check the typed Element stack associated with an iptable instance
    int num[5] = {0,1,2,3,4};
    table_t *ipt = tbl_create(NULL);

    mu_assert(ipt);

    tbl_stackpush(ipt, 0, &num[0]);
    tbl_stackpush(ipt, 1, &num[1]);
    tbl_stackpush(ipt, 2, &num[2]);
    tbl_stackpush(ipt, 3, &num[3]);
    tbl_stackpush(ipt, 4, &num[4]);
    mu_assert(ipt->size == 5);
    mu_assert(ipt->top != NULL);

    mu_assert(*(int *)ipt->top->elm == 4);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 3);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 2);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 1);
    tbl_stackpop(ipt);
    mu_assert(*(int *)ipt->top->elm == 0);
    tbl_stackpop(ipt);

    mu_assert(ipt->size == 0);
    mu_assert(ipt->top == NULL);

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_stack_pop(void)
{
    // check the typed Element stack associated with an iptable instance
    table_t *ipt = tbl_create(NULL);
    mu_assert(ipt);

    mu_false(tbl_stackpop(ipt));  // popping an empty stack yields 0

    tbl_destroy(&ipt, NULL);
}

void
test_tbl_stack_again(void)
{
    // these tests store int data from a int char on the stack, rather than the
    // heap, so we donot need a purge fuction

    char pfx[MAX_STRKEY];
    int type, types[5] = {0,0,0,0,0}, number[7] = {1, 2, 4, 8, 16, 32, 64};
    int leafs = 0;
    table_t *ipt = tbl_create(NULL);
    void *ptr;

    mu_assert(ipt);

    // add a few prefixes and test number of certain node types

    // 4 ipv4 prefixes, with 4 unique masks
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/24");
    mu_assert(tbl_set(ipt, pfx, number+0, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/25");  // dupedkey w/ different mask
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "1.1.1.0/26");  // dupedkey w/ different mask
    mu_assert(tbl_set(ipt, pfx, number+1, NULL));
    snprintf(pfx, MAX_STRKEY, "2.1.1.0/27");
    mu_assert(tbl_set(ipt, pfx, number+2, NULL));

    // 2 ipv6 prefixes, with 2 unique masks
    snprintf(pfx, MAX_STRKEY, "2f:aa:bb::/120");
    mu_assert(tbl_set(ipt, pfx, number+5, NULL));
    snprintf(pfx, MAX_STRKEY, "3f:aa:bb::/128");
    mu_assert(tbl_set(ipt, pfx, number+6, NULL));

    leafs = 0;
    mu_assert(rdx_firstnode(ipt, AF_INET));
    while(ipt->top) {
        mu_assert(rdx_nextnode(ipt, &type, &ptr));
        if (type > -1 && type < 5)
            types[type] += 1;
        else
            mu_false("unknown TRDX-type encountered!");
        if (type == TRDX_NODE &&
            RDX_ISLEAF(((struct radix_node *)ptr)) &&
            !RDX_ISROOT(((struct radix_node *)ptr)))
                leafs += 1;
    }
    // stack must exhausted
    mu_assert(ipt->top == NULL);
    mu_eq((size_t)0, ipt->size, "stack size (%lu)");

    /* The tree has have:
     * - 1 ipv4 radix_node_head and 1 ipv4 radix_mask_head, plus
     * - 1 ipv6 radix_node_head and 1 ipv6 radix_mask_head
     * We traversed the ipv4 tree.
     */
    mu_eq(1, types[TRDX_NODE_HEAD], "%d radix_node_head's");
    mu_eq(1, types[TRDX_MASK_HEAD], "%d radix_mask_head's");

    /* The tree has:
     * - 4 ipv4 prefix-leafs + 4 ipv4 mask-leafs (num of different ipv4 masks)
     * - 2 ipv6 prefix-leafs + 2 ipv6 mask-leafs (num of different ipv6 masks)
     */
    mu_eq(4+4, leafs, "%d node leafs");


    /*
     * repeat the tests for IPv6
     */

    leafs = 0;
    mu_assert(rdx_firstnode(ipt, AF_INET6));
    while(ipt->top) {
        mu_assert(rdx_nextnode(ipt, &type, &ptr));
        if (type > -1 && type < 5)
            types[type] += 1;
        else
            mu_false("unknown TRDX-type encountered!");
        if (type == TRDX_NODE &&
            RDX_ISLEAF(((struct radix_node *)ptr)) &&
            !RDX_ISROOT(((struct radix_node *)ptr)))
                leafs += 1;
    }
    // stack must exhausted
    mu_assert(ipt->top == NULL);
    mu_eq((size_t)0, ipt->size, "stack size (%lu)");

    /* The tree has have:
     * - 1 ipv4 radix_node_head and 1 ipv4 radix_mask_head, plus
     * - 1 ipv6 radix_node_head and 1 ipv6 radix_mask_head
     * We traversed the ipv6 tree.  The types stats of the ipv4 traversal are
     * updated with the stats of the ipv6 traversel.
     */

    mu_eq(2, types[TRDX_NODE_HEAD], "%d radix_node_head's");
    mu_eq(2, types[TRDX_MASK_HEAD], "%d radix_mask_head's");

    /* The tree has:
     * - 4 ipv4 prefix-leafs + 4 ipv4 mask-leafs (num of different ipv4 masks)
     * - 2 ipv6 prefix-leafs + 2 ipv6 mask-leafs (num of different ipv6 masks)
     * leafs was reset, so we should have 4 ipv6 leafs.
     */
    mu_eq(2+2, leafs, "%d node leafs");

    tbl_destroy(&ipt, NULL);
}
