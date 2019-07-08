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
#include "test_c_tbl_stackops.h"

#define NELEMS(x)  ((int)(sizeof(x) / sizeof(x[0])))

/*
 * tbl_stackpush() and tbl_stackpop()
 *
 * implement a simple stack to facilitate iteration across all nodes of all
 * types used in the radix trees (both key-tree as well as mask-tree).
 *
 * Not used for 'production' but to allow ipt2dot.lua to produce a dot-file for
 * a given AF_family's radix tree.
 *
 */

void
test_tbl_stackpop_null(void)
{
    /* fails ignores NULL pointers to table or to stack itself */
    table_t t;
    t.top = NULL;

    mu_eq(0, tbl_stackpop(NULL), "stackpop return val %d");
    mu_eq(0, tbl_stackpop(&t), "stackpop return val %d");
}

void
test_tbl_stackpush_null(void)
{
    int n = 42;

    mu_eq(0, tbl_stackpush(NULL, n, (void *)&n), "stack push return val %d");
}

void
test_tbl_stack_size(void)
{
    /* stack size is informational only */

    table_t *t = tbl_create(NULL);
    int count = 42;

    tbl_stackpush(t, count, (void *)&count);
    tbl_stackpush(t, count, (void *)&count);
    tbl_stackpush(t, count, (void *)&count);

    /* mangle stack size and see no effect */
    t->size -= 10;

    count = 0;
    while(t->top) {
        tbl_stackpop(t);
        count += 1;
    }
    mu_eq(3, count, "stack size %d");

    /* an exhausted stack has its size set back to zero */
    mu_eq((size_t)0, t->size, "exhausted stack size %lu");

    tbl_destroy(&t, NULL);

}

/*
 * The stack lets you push/pop values with a certain type.
 *
 */

void
test_tbl_stack_types(void)
{
    int types[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

    table_t *t = tbl_create(NULL);

    for (int i = 0; i < NELEMS(types); i++)
        tbl_stackpush(t, types[i], (void *)&types[i]);

    mu_eq(NELEMS(types), (int)t->size, "nelems on stack %d");

    /* pop and check each type is its own value */
    while (t->top) {
        mu_eq(t->top->type, *(int *)t->top->elm, "elm type %d");
        tbl_stackpop(t);
    }
    mu_eq(NULL, (void *)t->top, "stack top %p");
    mu_eq((size_t)0, t->size, "stack size %lu");

    tbl_destroy(&t, NULL);
}
