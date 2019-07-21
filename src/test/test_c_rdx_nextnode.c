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
#include "test_c_rdx_nextnode.h"

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)(x))

/*
 * Test tbl's stack for iterating across radix nodes of all types.
 *
 * nextnode(table_t *t, int *type, void **ptr) returns top of the stack:
 * - pops the top
 * - pushes its progeny
 * - sets type to type of popped top element
 * - sets ptr to popped top element
 * - return 1 on success, 0 on failure
 */

void
test_rdx_nextnode(void)
{
    struct radix_node_head *rnh = NULL;
    struct radix_mask_head *rmh = NULL;
    int type;
    table_t *ipt = tbl_create(NULL);  // empty but valid iptable instance

    mu_assert(ipt);
    mu_assert(rdx_firstnode(ipt, AF_INET));
    mu_assert(ipt->size == 1);  // t.top -> [head4]

    // pop head4, its progeny should have been pushed
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rnh));
    // stack -> [head4->rh.rnh_masks]
    mu_eq(TRDX_NODE_HEAD, type, "%d");
    mu_assert(ipt->head4 == rnh);
    mu_assert(ipt->size == 1);

    // pop head4's radix_mask_head, no progeny pushed (empty table)
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rmh));
    // stack -> []
    mu_eq(TRDX_MASK_HEAD, type, "%d");
    mu_assert(ipt->head4->rh.rnh_masks == rmh);
    mu_assert(ipt->size == 0);

    /* repeat the process for IPv6 */
    mu_assert(rdx_firstnode(ipt, AF_INET6));
    // pop head6, its progeny should have been pushed
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rnh));
    // stack -> [head6->rh.rnh_masks]
    mu_eq(TRDX_NODE_HEAD, type, "%d");
    mu_assert(ipt->head6 == rnh);
    mu_assert(ipt->size == 1);

    // pop head6's radix_mask_head, no progeny pushed (empty table)
    mu_assert(rdx_nextnode(ipt, &type, (void **)&rmh));
    // stack -> []
    mu_eq(TRDX_MASK_HEAD, type, "%d");
    mu_assert(ipt->head6->rh.rnh_masks == rmh);
    mu_assert(ipt->size == 0);
    mu_assert(ipt->top == NULL);

    tbl_destroy(&ipt, NULL);
}

