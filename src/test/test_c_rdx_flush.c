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
#include "test_c_rdx_flush.h"

/*
 * rdx_flush() - free tree key & user controlled resources if applicable
 *
 * - rdx_flush ALWAYS returns 0.
 *
 */

void
test_rdx_flush_null(void)
{
    struct radix_node rn;
    int arg = 0;

    /* handles NULL for *rn as well as *args, both must be non-null */
    mu_false(rdx_flush(NULL, NULL));
    mu_false(rdx_flush(&rn, NULL));
    mu_false(rdx_flush(NULL, &arg));
}

/*
 * need a better way to test rdx_flush ... but the func is meant to be used
 * in iptable.c only while walking the tree when destroying it.  Not meant to
 * be invoked by usercode...
 *
 */

void
test_rdx_flush_freekey(void)
{
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node *rn = NULL;
    struct purge_t purge;
    int mlen, af;
    table_t *t = tbl_create(NULL);

    purge.purge = NULL;
    purge.head = t->head4;
    purge.args = NULL;

    tbl_set(t, "1.1.1.1/24", &af, NULL);
    mu_true(key_bystr(addr, &mlen, &af, "1.1.1.1"));
    mu_true(key_bylen(mask, 24, af));
    rn = t->head4->rnh_lookup(addr, mask, &t->head4->rh);

    if(rn) {

        /* flush the entry via rdx_flush */
        mu_eq(0, rdx_flush(rn, &purge), "rdx_flush return val %d");
        rn = t->head4->rnh_lookup(addr, mask, &t->head4->rh);
        mu_eq(NULL, (void *)rn, "flushed node %p");

    } else
        mu_failed("expected to find rn, not %p", (void*)rn);

    tbl_destroy(&t, NULL);
    mu_eq(NULL, (void *)t, "tree ptr %p");
}
