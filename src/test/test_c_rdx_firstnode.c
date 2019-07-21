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
#include "test_c_rdx_firstnode.h"

#define INT_VALUE(x) (*(int *)x->value)
#define SIZE_T(x) ((size_t)(x))

/*
 * An iptable has a stack specifically for radixes(), which iterates across
 * all possible radix nodes, of all types, in a AF_family's radix tree.
 *
 * Stack operations are implemented by:
 * rdx_firstnode(table_t *t, int af_fam)
 * rdx_nextnode(table_t *t, int *type, void **ptr)
 * tbl_stackpush(table_t *t, int type, void *ptr)
 * tbl_stackpop(table_t *t)
 *
 * This file tests rdx_firstnode which pushes the radix node head of af_fam's
 * radix tree.
 *
 */

void
test_rdx_firstnode(void)
{
    table_t *ipt = tbl_create(NULL);
    mu_assert(ipt);

    mu_assert(rdx_firstnode(ipt, AF_INET));
    mu_assert(ipt->size == 1);
    mu_assert(ipt->top->type == TRDX_NODE_HEAD);
    mu_assert(ipt->top->elm  == ipt->head4);

    mu_assert(tbl_stackpop(ipt));

    mu_assert(rdx_firstnode(ipt, AF_INET6));
    mu_assert(ipt->size == 1);
    mu_assert(ipt->top->type == TRDX_NODE_HEAD);
    mu_assert(ipt->top->elm  == ipt->head6);

    tbl_destroy(&ipt, NULL);
}
