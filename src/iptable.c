#include <stdio.h>        // printf
#include <sys/types.h>    // u_char
/* #include <sys/socket.h> */
#include <stddef.h>       // offsetof
#include <stdlib.h>       // malloc / calloc
// #include <netinet/in.h>   // sockaddr_in
#include <arpa/inet.h>    // inet_pton and friends
#include <string.h>       // strlen
#include <ctype.h>        // isdigit

#include "radix.h"
#include "iptable.h"

/* static char rn_zeros[RDX_MAX_KEYLEN]; */
/* needed for masking a key
static uint8_t  rn_ones[RDX_MAX_KEYLEN] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
};
*/

// -- KEY funcs

uint8_t *
key_bystr(char *s, int *mlen)
{
    // on success, sets mlen & returns a ptr to key
    // - mlen = -1 when no prefix length was supplied
    // on failure returns NULL and mlen is undefined

    uint8_t *addr;                                // the address as key ptr
    *mlen = -1;                                   // the mask as length

    int a, b, c, d, n;
    char *slash;
    // char buf[1 + IP6_PFXSTRLEN];

    if (s == NULL) return NULL;                   // need prefix string
    if (strlen(s) > IP6_PFXSTRLEN) return NULL;   // invalid string length

    slash = strchr(s, '/');                       // pick up mask, if any
    if (slash) {
        sscanf(slash, "/%i%n", mlen, &n);
        if (*(slash + n)) return NULL;            // no valid /mask ending
        if (*mlen < 0) return NULL;               // dito
    }

    if (STR_IS_IP6(s)) {
        if (*mlen > IP6_MAXMASK) return NULL;
        addr = calloc(sizeof(uint8_t), 1 + IP6_KEYLEN);
        if (addr == NULL) return NULL;            // mem error
        IPT_KEYLEN(addr) = 1 + IP6_KEYLEN;        // +1 for length byte
        if (slash) *slash = '\0';                 // just for inet_pton
        inet_pton(AF_INET6, s, IPT_KEYPTR(addr));
        if (slash) *slash = '/';                  // restore s
        return addr;

    } else {
        // use scanf to support normal shorthand notation:
        // - 10.10/16 means 10.10.0.0/16, *not* 10.0.0.10/16
        // %i scans hex (0x..), octal (0..) or base 10 ([1-9]..)
        // -> so 1.2.3.008 is actually an illegal octal number ...

        if (*mlen > IP4_MAXMASK) return NULL;
        if (!isdigit(*s)) return NULL; // must start with 0x, 0, or [1-9]

        a = b = c = d = n = 0;
        sscanf(s, "%i%n.%i%n.%i%n.%i%n", &a, &n, &b, &n, &c, &n, &d, &n);
        if(n > 0 && *(s+n) != '/' && *(s+n) != '\0')
            return NULL; // malformed digits

        // check validity of digits
        if(a < 0 || a > 255) return NULL;
        if(b < 0 || b > 255) return NULL;
        if(c < 0 || c > 255) return NULL;
        if(d < 0 || d > 255) return NULL;

        // snprintf(buf, INET_ADDRSTRLEN, "%d.%d.%d.%d", a, b, c, d);
        addr = calloc(sizeof(uint8_t), 1 + IP4_KEYLEN);
        if (addr == NULL) return NULL;                 // mem error
        IPT_KEYLEN(addr) = 1 + IP4_KEYLEN;
        *(addr+1) = a;  // bigendian, so a goes first
        *(addr+2) = b;
        *(addr+3) = c;
        *(addr+4) = d;
        /* inet_pton(AF_INET, buf, IPT_KEYPTR(addr)); */
        return addr;
    }

    return NULL;  // failed
}

uint8_t *
key_bylen(int af, int mlen)
{
    // returns ptr to key when succesfull, NULL otherwise
    uint8_t *key, *cp;
    int size;

    // check: valid mask length, corresponding to valid AF_family
    if(af == AF_INET6) {
        mlen = mlen == -1 ? IP6_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP6_MAXMASK) return NULL;
    } else if (af == AF_INET) {
        mlen = mlen == -1 ? IP4_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP4_MAXMASK) return NULL;
    } else return NULL;

    size = (af == AF_INET6) ? 1 + IP6_KEYLEN : 1 + IP4_KEYLEN;
    if (!(key = calloc(sizeof(*key), size)))
        return NULL;                                      // mem error

    IPT_KEYLEN(key) = size;                               // set keylen byte
    cp = IPT_KEYPTR(key);
    while (--size > 0) {                                  // set all key bytes
        *(cp++) = mlen > 8 ? 0xff : ~((1 << (8 - mlen))-1);
        mlen = mlen > 8 ? mlen - 8 : 0;
    }

    return key;  // caller must free(key)
}

int key_tolen(void *key)
{
    // counts the nr of consequtive 1-bits starting with the MSB first.
    // - a radix mask key's KEYLEN indicates the num of non-zero bytes in the
    //   mask.  Hence, it may be smaller than 1+IP{4,6}_KEYLEN

    int size = 0, cnt = 0;
    uint8_t *cp;

    // sanity check
    if (key == NULL) return -1;

    size = IPT_KEYLEN((uint8_t *)key);        // nr of bytes in key
    cp = IPT_KEYPTR((uint8_t *)key);          // pick up start of key

    // count bits of all-1's bytes
    for(; --size > 0 && *cp == 0xff; cnt += 8, cp++)
        ;

    if (size == 0) return cnt;               // got them all

    // count 1-bits from MSB to LSB stopping at first 0-bit
    for (uint8_t m=0x80; m > 0 && *cp & m; m = m >> 1, cnt++)
        ;

    return cnt;
}

const char *
key_tostr(void *k, char *s)
{
    // uses void *k so rn-keys (char *) are handled as well
    uint8_t *key = k;

    if (s == NULL || k == NULL) return NULL;

    if(KEY_IS_IP6(key)) {
        return inet_ntop(AF_INET6, IPT_KEYPTR(key), s, INET6_ADDRSTRLEN);
    }
    return inet_ntop(AF_INET, IPT_KEYPTR(key), s, INET_ADDRSTRLEN);
}

int
key_incr(void *key)
{
    // 1 on success, 0 on failure (incr key, flips around from max to 0)
    uint8_t *k = key;
    if (k == NULL) return 0;

    int off = IPT_KEYLEN(k);
    if (off < 1) return 0;

    while(!(*(k + --off)+=1))
        ;

    return 1;
}

int
key_decr(void *key)
{
    // decrement the key, flips around from 0 to max
    uint8_t *k = key;
    if (k == NULL) return 0;

    int off = IPT_KEYLEN(k);
    while(--off > 0 && ((*(k+off)-=1)==255))
        ;

    return 1;
}

int
key_masked(void *key, void *mask)
{
    // apply mask to key, 1 on success, 0 on failure
    // - a mask's length may indicate the num of non-zero bytes instead of the
    //   entire length of the mask byte array.  Such 'missing' bytes are taken
    //   to be 0x00 (some radix tree masks seem to do this).
    int klen, mlen;
    uint8_t *k = key, *m = mask;

    // sanity check
    if (k == NULL || m == NULL) return 0;
    klen = IPT_KEYLEN(k);
    mlen = IPT_KEYLEN(m);
    k = IPT_KEYPTR(k);      // skip LEN byte
    m = IPT_KEYPTR(m);      // skip LEN byte

    if (klen < mlen) return 0;  // donot overrun key
    for(mlen--; --klen; mlen--)
        *(k++) &= mlen > 0 ? *(m++) : 0x00;

    return 1;
}

int
key_cmp(void *a, void *b)
{
    // -1 if a<b, 0 if a==b, 1 if a>b, -2 on errors
    uint8_t keylen, *aa = a, *bb = b;

    if (aa == NULL || bb == NULL) return -2;       // need real keys
    keylen = IPT_KEYLEN(aa);
    if (keylen != IPT_KEYLEN(bb)) return -2;       // different AF_families

    while(--keylen > 0 && (*aa++ == *bb++))        // includes len byte in cmp
        ;

    if (*aa < *bb) return -1;
    if (*aa > *bb) return 1;
    return 0;
}

// -- radix node operations

int
rdx_flush(struct radix_node *rn, void *arg)
{
    // return 0 on success, 1 on failure (see rnh_walktree)

    // A radix leaf node == entry: {radix_node rn[2], void *value}
    // - rdx_flush called on LEAF nodes (rn actually points to entry->rn[0])
    struct entry_t *entry = NULL;
    struct radix_node_head * rnh = arg;

    if (rn == NULL) return 0;
    entry = (entry_t *)rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, &rnh->rh);
    if (entry == NULL) return 0;
    if(entry->value != NULL) free(entry->value);  // free user data, if any
    free(entry->rn[0].rn_key);                    // same as rn->rn_key
    free(entry);
    return 0;
}

// -- TABLE funcs

table_t *
tbl_create(void)
{
    // create a new iptable w/ 2 radix trees
    table_t *tbl = NULL;

    tbl = calloc(sizeof(*tbl), 1);  // sets count's to zero & ptr's to NULL
    if (tbl == NULL) return NULL;

    if (rn_inithead((void **)&tbl->head4, 8) == 0) { // IPv4 radix tree
        free(tbl);
        return NULL;
    }
    if (rn_inithead((void **)&tbl->head6, 8) == 0) { // IPv6 radix tree
        rn_detachhead((void **)&tbl->head4);
        free(tbl);
        return NULL;
    }

    return tbl;
}

int
tbl_walk(table_t *t, walktree_f_t *f)
{
    // run func f() on leafs in IPv4 tree and IPv6 tree
   if (t == NULL) return 0;

   t->head4->rnh_walktree(&t->head4->rh, f, t->head4);
   t->head6->rnh_walktree(&t->head6->rh, f, t->head6);

   return 1;
}


void
tbl_destroy(table_t **t)
{
    if (t == NULL || *t == NULL) return;  // already freed

    tbl_walk(*t, rdx_flush);  // delete all leaf nodes
    rn_detachhead((void **)&(*t)->head4);
    rn_detachhead((void **)&(*t)->head6);

    free(*t);
    *t = NULL;
}

int
tbl_add(table_t *t, char *s, void *v)
{
    // A missing mask is taken to mean AF's max mask
    // Always applies mask to addr before adding to the tree

    // If key already exists -> free both s-derived key & mask
    // otherwise, only free the s-derived mask (tree now 'owns' the key).
    uint8_t *addr = NULL, *mask = NULL;
    int mlen = -1;
    entry_t *entry = NULL;  // is struct { radix_node rn[2], void *value}
    struct radix_node *rn = NULL;
    struct radix_node_head *head = NULL;

    if (t == NULL) return 0;

    addr = key_bystr(s, &mlen);
    if (addr == NULL) goto bail;

    if (KEY_IS_IP6(addr)) {
        head = t->head6;
        mask = key_bylen(AF_INET6, mlen);
    } else if (KEY_IS_IP4(addr)) {
        head = t->head4;
        mask = key_bylen(AF_INET, mlen);
    } else goto bail;

    if (mask == NULL) goto bail;
    if (! key_masked(addr, mask)) goto bail;
    rn = head->rnh_lookup(addr, mask, &head->rh); // exact match for pfx
    if (rn) {
        // update existing entry
        free(addr);
        free(mask);
        entry = (entry_t *)rn;
        entry->value = v;
        return 1;
    } else {
        // add new entry
        if (!(entry = calloc(sizeof(*entry),1)))  // init'd to all zeros
            goto bail;
        entry->value = v;
        rn = head->rnh_addaddr(addr, mask, &head->rh, entry->rn);
        if (!rn)
            goto bail;

        if (KEY_IS_IP6(addr)) t->count6++;
        else t->count4++;

        // alway free the mask, never the key
        if (mask != NULL) free(mask);

        return (1);
    }

bail:
    if (addr) free(addr);
    if (mask) free(mask);
    if (entry && entry->value) free(entry->value);
    if (entry) free(entry);
    return 0;
}

int
tbl_del(table_t *t, char *s)
{
    // Deletion requires exact match on prefix
    // Missing mask is taken to mean AF's max mask
    struct radix_node *rn = NULL;
    struct radix_node_head *head = NULL;
    uint8_t *addr = NULL, *mask = NULL;
    int mlen = -1, rv = 0;

    if (t == NULL) return 0;

    addr = key_bystr(s, &mlen);
    if (addr == NULL) goto bail;
    if (KEY_IS_IP6(addr)) {
        head = t->head6;
        mask = key_bylen(AF_INET6, mlen);
    } else if (KEY_IS_IP4(addr)) {
        head = t->head4;
        mask = key_bylen(AF_INET, mlen);
    } else goto bail;

    if (mask == NULL) goto bail;
    if (! key_masked(addr, mask)) goto bail;
    rn = head->rnh_lookup(addr, mask, &head->rh); // exact match for pfx
    if (rn) {
        if (KEY_IS_IP6(addr)) t->count6--;
        else t->count4--;
        rdx_flush(rn, head);
        rv = 1; // return value for success
    }

bail:
    if (addr) free(addr);
    if (mask) free(mask);
    return rv;
}

entry_t *
tbl_lpm(table_t *t, char *s)
{
    // longest prefix match for address (any /mask is ignored)
    struct radix_node_head *head = NULL;
    uint8_t *addr = NULL;
    int mlen = -1;
    entry_t *rv = NULL;

    if (t == NULL) return 0;

    addr = key_bystr(s, &mlen);
    if (addr == NULL) goto bail;
    else if (KEY_IS_IP6(addr))
        head = t->head6;
    else if (KEY_IS_IP4(addr))
        head = t->head4;
    else goto bail;

    rv = (entry_t *)head->rnh_matchaddr(addr, &head->rh);

bail:
    if (addr) free(addr);
    return rv;
}

int
main(void)
{
    printf("no main here\n");
}
