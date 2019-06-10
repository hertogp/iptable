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

// -- helpers

// -- KEY funcs
uint8_t *
key_alloc(int af)
{
    uint8_t *key = NULL, keylen = 0;

    if (af == AF_INET)
        keylen = 1 + IP4_KEYLEN;               // 5
    else if (af == AF_INET6)
        keylen = 1 + IP6_KEYLEN;               // 17
    else return NULL;                          // unknown AF family

    key = calloc(sizeof(uint8_t), keylen);     // zero initialized
    if (key) IPT_KEYLEN(key) = keylen;         // set LEN byte

    return key;
}

uint8_t *
key_copy(uint8_t *src)
{
    uint8_t *key = key_alloc(KEY_AF_FAM(src));
    if (key == NULL) return NULL;
    memcpy(key, src, IPT_KEYLEN(key));

    return key;
}
uint8_t *
key_bystr(char *s, int *mlen, int *af)
{
    // on success, sets mlen, af & returns a ptr to key
    // - mlen = -1 when no prefix length was supplied
    // on failure returns NULL and mlen is undefined

    uint8_t *addr = NULL;                         // the address as key ptr
    *mlen = -1;                                   // the mask as length
    *af = AF_UNSPEC;

    int a, b, c, d, n;
    char *slash;
    // char buf[1 + IP6_PFXSTRLEN];

    if (s == NULL) return NULL;                   // need prefix string
    if (strlen(s) > IP6_PFXSTRLEN) return NULL;   // invalid string length
    if (strlen(s) < 1) return NULL;               // invalid string length

    slash = strchr(s, '/');                       // pick up mask, if any
    if (slash) {
        sscanf(slash, "/%i%n", mlen, &n);
        if (*(slash + n)) return NULL;            // no valid /mask ending
        if (*mlen < 0) return NULL;               // dito
    }

    if (STR_IS_IP6(s)) {
        if (*mlen > IP6_MAXMASK) return NULL;
        addr = key_alloc(AF_INET6);
        if (addr == NULL) return NULL;            // mem error
        if (slash) *slash = '\0';                 // just for inet_pton
        inet_pton(AF_INET6, s, IPT_KEYPTR(addr));
        if (slash) *slash = '/';                  // restore s
        *af = AF_INET6;
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

        addr = key_alloc(AF_INET);
        if (addr == NULL) return NULL;                 // mem error
        *(addr+1) = a;  // bigendian, so a goes first
        *(addr+2) = b;
        *(addr+3) = c;
        *(addr+4) = d;
        *af = AF_INET;
        return addr;
    }

    return NULL;  // failed
}

/* uint8_t * */
/* key_bylen(int af, int mlen) */
/* { */
/*     // returns ptr to key for AF_family when succesfull, NULL otherwise */
/*     uint8_t *key, *cp; */
/*     int size; */

/*     // check: valid mask length, corresponding to valid AF_family */
/*     if(af == AF_INET6) { */
/*         mlen = mlen == -1 ? IP6_MAXMASK : mlen; */
/*         if (mlen < 0 || mlen > IP6_MAXMASK) return NULL; */
/*     } else if (af == AF_INET) { */
/*         mlen = mlen == -1 ? IP4_MAXMASK : mlen; */
/*         if (mlen < 0 || mlen > IP4_MAXMASK) return NULL; */
/*     } else return NULL; */

/*     key = key_alloc(af); */
/*     if (key == NULL) return NULL; */

/*     size = IPT_KEYLEN(key); */
/*     cp = IPT_KEYPTR(key); */
/*     while (--size > 0) {                                  // set all key bytes */
/*         *(cp++) = mlen > 8 ? 0xff : ~((1 << (8 - mlen))-1); */
/*         mlen = mlen > 8 ? mlen - 8 : 0; */
/*     } */

/*     return key;  // caller must free(key) */
/* } */

uint8_t *
key_bylen(int af, int mlen, uint8_t *buf)
{
    // create key by masklength, store result in buf.  Retuns NULL on failure.
    // buf is typically uint8_t buf[IPT_KEYBUFLEN]
    uint8_t *cp;
    int keylen;

    // check: valid mask length, corresponding to valid AF_family
    if(af == AF_INET6) {
        mlen = mlen == -1 ? IP6_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP6_MAXMASK) return NULL;
        keylen = 1 + IP6_KEYLEN;
    } else if (af == AF_INET) {
        mlen = mlen == -1 ? IP4_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP4_MAXMASK) return NULL;
        keylen = 1 + IP4_KEYLEN;
    } else return NULL;

    IPT_KEYLEN(buf) = keylen;
    cp = IPT_KEYPTR(buf);
    while (--keylen > 0) {                              // set all key bytes
        *(cp++) = mlen > 8 ? 0xff : ~((1 << (8 - mlen))-1);
        mlen = mlen > 8 ? mlen - 8 : 0;
    }

    return buf;
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

    if (size <= 0) return cnt;               // got them all

    // count 1-bits from MSB to LSB stopping at first 0-bit
    for (uint8_t m=0x80; m > 0 && *cp & m; m = m >> 1, cnt++)
        ;

    return cnt;
}

const char *
key_tostr(void *k, char *s)
{
    // uses void *k so rn-keys (char *) are handled as well
    // user supplied buffer s must be large enough to hold an IPv6 prefix
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
key_invert(void *key)
{
  // invert a key, usefull for a mask.  LEN-byte does not change, so that
  // disrupts the idea that, for a mask, the LEN-byte indicates the number of
  // non-zero's bytes in the array, counting from the left.
  uint8_t *k = key;
  int klen;

  if (k == NULL) return 0;
  klen = IPT_KEYLEN(k);
  while(--klen > 0 && k++) *k = ~*k;

  return 1;
}

int
key_network(void *key, void *mask)
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
key_broadcast(void *key, void *mask)
{
    // apply (xor) inv.mask to key, 1 on success, 0 on failure
    // - a mask's length may indicate the num of non-zero bytes instead of the
    //   entire length of the mask byte array.  Such 'missing' bytes are taken
    //   to be 0xff (some radix tree masks seem to do this).
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
        *(k++) |= mlen > 0 ? ~*(m++) : 0xff;

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

    for(; --keylen > 0 && *aa==*bb; aa++, bb++)
        ;

    if (*aa < *bb) return -1;
    if (*aa > *bb) return 1;
    return 0;
}

// -- TABLE funcs

table_t *
tbl_create(purge_f_t *fp)
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
    tbl->purge = fp;

    return tbl;
}

int
rdx_flush(struct radix_node *rn, void *args)
{
    // return 0 on success, 1 on failure (see rnh_walktree)
    // - rdx_flush is called only on  _LEAF_ nodes (rn points to entry->rn[0])
    struct entry_t *entry = NULL;
    purge_t *arg = (purge_t *)args;
    struct radix_node_head *rnh = arg->head;

    if (rn == NULL) return 0;
    entry = (entry_t *)rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, &rnh->rh);
    if (entry == NULL) return 0;

    free(entry->rn[0].rn_key);
    if (entry->value != NULL) arg->purge(arg->args, &entry->value);
    free(entry);

    return 0;
}

struct radix_node *
rdx_first(struct radix_node_head *rnh)
{
    // find first leaf in tree
    struct radix_node *rn = NULL;

    if (rnh == NULL) return rn;

    rn = rnh->rh.rnh_treetop;
    while(rn->rn_bit >= 0)
        rn = rn->rn_left;

    while(RDX_ISRIGHT_CHILD(rn))
        rn = rn->rn_parent;

    for(rn = rn->rn_parent->rn_right; rn->rn_bit >=0;)
        rn = rn->rn_left;

    if(RDX_ISROOT(rn)) return NULL;

    return rn;
}

struct radix_node *
rdx_next(struct radix_node *rn)
{
    // find next leaf, given a leaf
    if (rn == NULL) return NULL;

    if (rn->rn_dupedkey)
        return rn->rn_dupedkey;

    while(RDX_ISRIGHT_CHILD(rn))
        rn = rn->rn_parent;

    for(rn = rn->rn_parent->rn_right; rn->rn_bit >=0;)
      rn = rn->rn_left;

    if (RDX_ISROOT(rn)) rn = NULL;

    return rn;
}

int
tbl_walk(table_t *t, walktree_f_t *f, void *fargs)
{
    // run f(args, leaf) on leafs in IPv4 tree and IPv6 tree
    if (t == NULL) return 0;
    t->head4->rnh_walktree(&t->head4->rh, f, fargs);
    t->head6->rnh_walktree(&t->head6->rh, f, fargs);

   return 1;
}

void
tbl_destroy(table_t **t, void *pargs)
{
    purge_t args;  // args to flush radix nodes & free userdata

    if (t == NULL || *t == NULL) return;  // nothing to free

    args.purge = (*t)->purge;          // the user callback to free userdata
    args.args = pargs;                 // context for purge callback

    args.head = (*t)->head4;
    (*t)->head4->rnh_walktree(&(*t)->head4->rh, rdx_flush, &args);
    rn_detachhead((void **)&(*t)->head4);

    args.head = (*t)->head6;
    (*t)->head6->rnh_walktree(&(*t)->head6->rh, rdx_flush, &args);
    rn_detachhead((void **)&(*t)->head6);

    free(*t);
    *t = NULL;
}

entry_t *
tbl_get(table_t *t, char *s)
{
    // An exact lookup for addr/mask, missing mask is set to AF's max mask
    uint8_t *addr = NULL;
    uint8_t mask[IPT_KEYBUFLEN];
    int mlen = -1, af = AF_UNSPEC;
    struct radix_node_head *head = NULL;
    entry_t *entry = NULL;

    if (t == NULL) return NULL;

    // get head, af, addr, mask, or bail on error
    addr = key_bystr(s, &mlen, &af);
    if (addr == NULL) goto bail;
    if (KEY_IS_IP6(addr)) head = t->head6;
    else if (KEY_IS_IP4(addr)) head = t->head4;
    else goto bail;

    if (! key_bylen(af, mlen, mask)) goto bail;
    if (! key_network(addr, mask)) goto bail;

    entry = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match for pfx

bail:
    if (addr) free(addr);
    return entry;
}

int
tbl_set(table_t *t, char *s, void *v, void *pargs)
{
    // A missing mask is taken to mean AF's max mask
    // - applies mask before searching/setting the tree
    uint8_t *addr = NULL;
    uint8_t mask[IPT_KEYBUFLEN];
    int mlen = -1, af = AF_UNSPEC;
    entry_t *entry = NULL;
    struct radix_node *rn = NULL;
    struct radix_node_head *head = NULL;

    if (t == NULL) return 0;

    // get head, af, addr, mask, or bail on error
    addr = key_bystr(s, &mlen, &af);
    if (addr == NULL) goto bail;
    if (KEY_IS_IP6(addr)) head = t->head6;
    else if (KEY_IS_IP4(addr)) head = t->head4;
    else goto bail;

    if (! key_bylen(af, mlen, mask)) goto bail;

    if (! key_network(addr, mask)) goto bail;

    entry = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match
    if (entry) {
        // update existing entry
        free(addr);
        if(entry->value) t->purge(pargs, &entry->value); // free userdata
        entry->value = v;                                // ptr-> new userdata
        return 1;

    } else {
        // add new entry, donot free key
        if (!(entry = calloc(sizeof(*entry),1)))  // init'd to all zeros
            goto bail;
        entry->value = v;
        rn = head->rnh_addaddr(addr, mask, &head->rh, entry->rn);
        if (!rn) goto bail;
        // update count
        if (KEY_IS_IP6(addr)) t->count6++;
        else t->count4++;

        return 1;
    }

bail:
    if (addr) free(addr);
    if (entry && entry->value) t->purge(pargs, &entry->value);
    if (entry) free(entry);
    return 0;
}

int
tbl_del(table_t *t, char *s, void *pargs)
{
    // Deletion requires exact match on prefix
    // - a missing mask is set to AF's max mask
    entry_t *e;
    struct radix_node_head *head = NULL;
    uint8_t *addr = NULL;
    uint8_t mask[IPT_KEYBUFLEN];
    int mlen = -1, rv = 0, af = AF_UNSPEC;
    if (t == NULL) return 0;

    // get head, af, addr, mask, or bail on error
    addr = key_bystr(s, &mlen, &af);
    if (addr == NULL) goto bail;
    if (KEY_IS_IP6(addr)) head = t->head6;
    else if (KEY_IS_IP4(addr)) head = t->head4;
    else goto bail;

    if (! key_bylen(af, mlen, mask)) goto bail;

    if (! key_network(addr, mask)) goto bail;

    if ((e = (entry_t *)head->rnh_deladdr(addr, mask, &head->rh))) {
      if (KEY_IS_IP6(addr)) t->count6--;
      else t->count4--;
      free(e->rn[0].rn_key);
      if(e->value) t->purge(pargs, &e->value);
      free(e);
      rv = 1;
    }

bail:
    if (addr) free(addr);
    return rv;
}

entry_t *
tbl_lpm(table_t *t, char *s)
{
    // longest prefix match for address (a /mask is ignored)
    struct radix_node_head *head = NULL;
    uint8_t *addr = NULL;
    int mlen = -1, af = AF_UNSPEC;
    entry_t *rv = NULL;

    if (t == NULL) return 0;

    addr = key_bystr(s, &mlen, &af);
    if (addr == NULL) goto bail;
    if (KEY_IS_IP6(addr)) head = t->head6;
    else if (KEY_IS_IP4(addr)) head = t->head4;
    else goto bail;

    rv = (entry_t *)head->rnh_matchaddr(addr, &head->rh);

bail:
    if (addr) free(addr);
    return rv;
}
