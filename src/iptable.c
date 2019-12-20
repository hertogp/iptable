/* # iptable.c
 */

#include <stdio.h>        // printf
#include <sys/types.h>    // u_char
// #include <sys/socket.h>
#include <stddef.h>       // offsetof
#include <stdlib.h>       // malloc / calloc
// #include <netinet/in.h>   // sockaddr_in
#include <arpa/inet.h>    // inet_pton and friends
#include <string.h>       // strlen
#include <ctype.h>        // isdigit

#include "radix.h"
#include "iptable.h"

/*
 *
 * ### `max_mask`
 *
 * ```c
 *  uint8_t max_mask[RDX_MAX_KEYLEN] = {-1, .., -1};
 *  ```
 *
 * `max_mask` serves as an AF family's default mask in case one is needed, but
 * not supplied.  Thus missing masks are interpreted as host masks.
 *
 */

uint8_t  max_mask[RDX_MAX_KEYLEN] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
};

/*
 * ## Key functions
 *
 */

/*
 * ### `key_alloc`
 * ```c
 *   uint8_t *key_alloc(int af);
 * ```
 *
 * Allocate space for a binary key of AF family type `af` and return its
 * pointer.  Supported `af` types include:
 * - `AF_INET`, for ipv4 protocol family
 * - `AF_INET6`, for the ipv6 protocol family
 *
 */

uint8_t *
key_alloc(int af)
{
    uint8_t *key = NULL, keylen = 0;

    if (af == AF_INET)
        keylen = IP4_KEYLEN;
    else if (af == AF_INET6)
        keylen = IP6_KEYLEN;
    else return NULL;                          // unknown AF family

    key = calloc(sizeof(uint8_t), keylen);     // zero initialized
    if (key) IPT_KEYLEN(key) = keylen;         // set LEN byte

    return key;
}

/*
 * ### `key_copy`
 * ```c
 *    uint8_t *key_copy(uint8_t *src);
 * ```
 * Copies binary key `src` into newly allocated space and returns its pointer.
 * The src key must have a valid first length byte.
 * $0 <= KEY\_LEN(src) <= MAX\_KEYLEN$.  Returns
 * `NULL` on failure.
 */

uint8_t *
key_copy(uint8_t *src)
{
    // assumes proper LEN-byte in the src byte array
    uint8_t *key = key_alloc(KEY_AF_FAM(src));
    if (key == NULL) return NULL;
    memcpy(key, src, IPT_KEYLEN(key));

    return key;
}

/*
 * ### `key_bystr`
 * ```c
 *    uint8_t *key_bystr(uint8_t *dst, int *mlen, int *af, const char *s);
 * ```
 * Store string s' binary key in dst. Returns NULL on failure.  Also sets mlen
 * and  af. mlen=-1 when no mask was supplied.  Assumes dst size MAX_BINKEY,
 * which fits both ipv4/ipv6.
 */

uint8_t *
key_bystr(uint8_t *dst, int *mlen, int *af, const char *s)
{

    *mlen = -1;                                   // the mask as length
    *af = AF_UNSPEC;
    char buf[MAX_STRKEY];

    int a, b, c, d, n;
    char *slash;

    // sanity checks
    if (dst == NULL) return NULL;
    if (s == NULL) return NULL;
    if (strlen(s) > MAX_STRKEY) return NULL;      // invalid string
    if (strlen(s) < 1) return NULL;               // invalid string

    // pick up mask, if present it must be valid
    slash = strchr(s, '/');
    if (slash) {
        sscanf(slash, "/%i%n", mlen, &n);
        if (*(slash + n)) return NULL;            // no valid /mask ending
        if (*mlen < 0) return NULL;               // dito
    }

    if (STR_IS_IP6(s)) {
        if (*mlen > IP6_MAXMASK) return NULL;
        strncpy(buf, s, INET6_ADDRSTRLEN);
        if(slash) buf[slash - s]='\0';
        IPT_KEYLEN(dst) = KEY_LEN_FAM(AF_INET6);
        inet_pton(AF_INET6, buf, IPT_KEYPTR(dst));
        *af = AF_INET6;
        return dst;

    } else {
        // use scanf to support shorthand notation: 10.10/16 is 10.10.0.0/16
        // %i scans hex (0x..), octal (0..) or base 10 ([1-9]..)
        if (strlen(s) > IP4_PFXSTRLEN) return NULL;
        if (*mlen > IP4_MAXMASK) return NULL;
        if (!isdigit(*s)) return NULL; // must start with 0x, 0, or [1-9]

        a = b = c = d = n = 0;
        sscanf(s, "%i%n.%i%n.%i%n.%i%n", &a, &n, &b, &n, &c, &n, &d, &n);
        if(n > 0 && *(s+n) != '/' && *(s+n) != '\0')
            return NULL; // malformed digits (or too many)

        // check validity of digits
        if(a < 0 || a > 255) return NULL;
        if(b < 0 || b > 255) return NULL;
        if(c < 0 || c > 255) return NULL;
        if(d < 0 || d > 255) return NULL;

        IPT_KEYLEN(dst) = KEY_LEN_FAM(AF_INET);
        *(dst+1) = a;  // bigendian, so 'a' goes first
        *(dst+2) = b;
        *(dst+3) = c;
        *(dst+4) = d;
        *af = AF_INET;
        return dst;
    }

    return NULL;  // failed
}

/*
 * ### `key_byfit`
 * ```c
 *   uint_8t *key_byfit(uint8_t *m, uint8_t *a, uint8_t *b)
 * ```
 * Set `m` to the largest possible mask for key `a` such that:
 * - `a`'s network address is still `a` itself, and
 * - `a`'s broadcast address is less than, or equal to, `b` address
 *
 * _Note: the function assumes a <= b._
 */

uint8_t *
key_byfit(uint8_t *m, uint8_t *a, uint8_t *b)
{
  uint8_t *x, *xmax, off=0;
  int af, trail = 0xFF;

  if ( m == NULL || a == NULL || b == NULL)
    return NULL;
  if (IPT_KEYLEN(a) != IPT_KEYLEN(b))
    return NULL;
  af = KEY_AF_FAM(a);
  if (AF_UNKNOWN(af))
    return NULL;
  *m = IPT_KEYLEN(a);  /* set mask's LEN byte */

  /* set mask bytes that honor 'a's lowest 1-bit and 'b' as a maximum */
  xmax = m + *m; x = m+1; a++; b++;
  for (; x < xmax; x++, a++, b++) {
    if (off) {
      *x = 0x00;
      trail &= *b;
    } else if (*a == *b) {
      *x = 0xFF;
    } else {
      /* runs once for 1st byte where a,b keys differ */
      off = xmax - x;
      *x = (*a & -*a)-1;
      while (*x > (*b - *a))
          *x = *x >> 1;
      *x = ~*x;
    }
  }

  /* need to ensure the broadcast address: (y|~m) <= z, since there are
   * trailing bytes < 0xFF.  So if the broadcast address, at the xmark spot
   * equals *z's byte, the mask needs to be expanded by 1 bit.
   */

  if (trail != 0xFF) {
    x = x - off; a = a - off; b = b -off;
    if ((0xFF & (*a | ~*x)) == *b)
      *x = 0x80 | (*x >> 1);
  }

  return m;
}

/* ### `key_bylen`
 * ```c
 *   uint8_t *key_bylen(uint8_t *binkey, int mlen, int af);
 * ```
 * Create a mask for given `af` family and mask length `mlen`.
 */

uint8_t *
key_bylen(uint8_t *binkey, int mlen, int af)
{
    // create key by masklength, store result in binkey.  Retuns NULL on failure.
    // assumes binkey size MAX_BINKEY
    uint8_t *cp;
    int keylen;

    // check: valid mask length, corresponding to valid AF_family
    if(af == AF_INET6) {
        mlen = mlen == -1 ? IP6_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP6_MAXMASK) return NULL;
        keylen = IP6_KEYLEN;
    } else if (af == AF_INET) {
        mlen = mlen == -1 ? IP4_MAXMASK : mlen;
        if (mlen < 0 || mlen > IP4_MAXMASK) return NULL;
        keylen = IP4_KEYLEN;
    } else return NULL;

    IPT_KEYLEN(binkey) = keylen;
    cp = IPT_KEYPTR(binkey);
    while (--keylen > 0) {                              // set all key bytes
        *(cp++) = mlen > 8 ? 0xff : ~((1 << (8 - mlen))-1);
        mlen = mlen > 8 ? mlen - 8 : 0;
    }

    return binkey;
}

/* ### `key_bypair`
 * ```c
 *   uint8_t * key_bypair(uint8_t *a, const void *b, const void *m);
 * ```
 * Set key a such that a/m and b/m are a pair that fit in key/m-1.
 * Assumes masks are contiguous.
 */

uint8_t *
key_bypair(uint8_t *a, const void *b, const void *m)
{
    uint8_t *aa = a, *last;
    const uint8_t *bb = b, *mm = m;

    if (aa == NULL || bb == NULL || mm == NULL) return NULL;
    /* fail on zero-length mask/key or mask that starts with 0 */
    if (*mm == 0 || *(mm+1) == 0 || *bb == 0) return NULL;
    /* ensure correct bounds on key/mask */
    if (*bb > MAX_BINKEY || *mm > MAX_BINKEY)
        return NULL;
    last = aa + *bb - 1; /* last key byte to write */

    for(*aa++ = *bb++, mm++; aa < last && *mm == 0xFF; mm++)
        *aa++ = *bb++;

    *aa = (*bb & *mm) ^ (1 + ~*mm);
    if (*mm == 0x00)
        *(aa-1) = *(aa-1) ^ 0x01;

    /* zero out any remaining key bytes */
    for(aa++; aa <= last; )
      *aa++ = 0x00;

    return a;
}

/* ### `key_masklen`
 * ```c
 *   int key_masklen(void *key);
 * ```
 * Count the number of consequtive 1-bits, starting with the msb first.
 */

int key_masklen(void *key)
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

/* ### `key_tostr`
 * ```c
 *   const char *key_tostr(char *dst, void *src);
 * ```
 */
const char *
key_tostr(char *dst, void *src)
{
    /*
     * src is byte array; 1st byte is usually total length of the array.
     *   - iptable.c keys/masks are uint8_t *'s (unsigned)
     *   - radix.c keys/masks  are char *'s. (may be signed; sys dependent)
     *   - radix.c keys/masks's KEYLEN may deviate: for masks it may indicate
     *     the total of non-zero bytes i/t array instead of its total length.
     */
    char *key = src;

    if (dst == NULL || src == NULL) return NULL;

    if(IPT_KEYLEN(key) > IP4_KEYLEN)
        return inet_ntop(AF_INET6, IPT_KEYPTR(key), dst, INET6_ADDRSTRLEN);

    return inet_ntop(AF_INET, IPT_KEYPTR(key), dst, INET_ADDRSTRLEN);
}


/*
 * ### `key_bynum`
 * ```c
 *   int key_bynum(void *key, size_t number);
 * ```
 * Create key from number. Returns NULL on failure, key otherwise.
 */

uint8_t *
key_bynum(uint8_t *key, size_t num, int af)
{
  uint8_t *x = key, tmp, *l, *r, max;

  if (key == NULL)
      return NULL;
  if ((max = KEY_LEN_FAM(af)) == 0)
      return NULL;

  *x++ = max;
  while (max-- > 1) {
    *x++ = num & 0xff;
    num >>= 8;
  }
  /* reverse the byte array */
  for (l=key+1, r=key+*key-1; l < r; l++, r--) {
    tmp = *l;
    *l = *r;
    *r = tmp;
  }

  return key;
}

/*
 * ### `key_incr`
 * ```c
 *   uint8_t *key_incr(uint8_t *key, size_t num);
 * ```
 * Increment `key` with `num`.  Returns key on success, NULL on failure (e.g.
 * when wrapping around the available address space) which usually means the
 * resulting `key` value is meaningless.
 */

uint8_t *
key_incr(uint8_t *key, size_t num)
{
  uint8_t *x = key, n, prev;

  if (key == NULL)
      return NULL;
  if (KEY_AF_FAM(key) == AF_UNSPEC)
      return NULL;

  for (x = x + *x -1; num && (x > key); x--) {
    n = num & 0xff;
    num >>= 8;
    prev = *x;
    *x += n;
    if (*x < prev)
        num++;
  }
  if (num > 0)
      return NULL;  /* wrapped around */

  return key;
}

/*
 * ### `key_decr`
 * ```c
 *   uint8_t *key_decr(uint8_t *key, size_t num);
 * ```
 * Decrement `key` with `num`. Returns `key` on success, NULL on failure (e.g.
 * when wrapping around the available address space) which usually means the
 * resulting `key` value is meaningless.
 */

uint8_t *
key_decr(uint8_t *key, size_t num)
{
  uint8_t *x = key, n, prev;

  if (key == NULL)
      return NULL;
  if (KEY_AF_FAM(key) == AF_UNSPEC)
      return NULL;

  for (x = x + *x -1; num && (x > key); x--) {
    n = num & 0xff;
    num >>= 8;
    prev = *x;
    *x -= n;
    if (*x > prev)
        num++;
  }
  if (num > 0)
      return NULL;  /* wrapped around */

  return key;
}

/*
 * ###`key_invert`
 * ```c
 *   int key_invert(void *key);
 * ```
 * inverts a key, usefull for a mask.  Assumes the LEN-byte indicates how many
 * bytes must be (and can be safely) inverted.
 */

int
key_invert(void *key)
{
  uint8_t *k = key;
  int klen;

  if (k == NULL) return 0;   /* no key, no inverted key */
  klen = IPT_KEYLEN(k);
  if (klen < 2) return 0;    /* key without bits cannot be inverted */

  while(--klen > 0 && k++) *k = ~*k;

  return 1;
}

/* ### `key_network`
 * ```c
 *   int key_network(void *key, void *mask);
 * ```
 */

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

    if (klen < 2) return 0;     // no key, no network address
    if (mlen > klen) return 0;  // donot overrun key
    for(mlen--; --klen; mlen--)
        *(k++) &= (mlen > 0) ? *(m++) : 0x00;

    return 1;
}

/* ### `key_broadcast`
 * ```c
 *   int key_broadcast(void *key, void *mask);
 * ```
 * set key to broadcast address, using mask
 * - 1 on success, 0 on failure
 * - mask LEN <= key LEN, 'missing' mask bytes are taken to be 0x00
 *   (a radix tree artifact).
 */

int
key_broadcast(void *key, void *mask)
{
    int klen, mlen;
    uint8_t *k = key, *m = mask;

    if (k == NULL || m == NULL) return 0;

    klen = IPT_KEYLEN(k);
    mlen = IPT_KEYLEN(m);

    if (klen < 2) return 0;      /* no key, no bcast address */
    if (mlen > klen) return 0;   /* mask may be smaller, never larger */

    k = IPT_KEYPTR(k);
    m = IPT_KEYPTR(m);

    for(mlen--; --klen; mlen--)
        *(k++) |= (mlen > 0) ? ~*(m++) : 0xff;

    return 1;
}

/* ### `key_cmp`
 * ```c
 *   int key_cmp(void *a, void *b);
 * ```
 * Returns -1 if a<b, 0 if a==b, 1 if a>b; or -2 on errors
 */

int
key_cmp(void *a, void *b)
{
    uint8_t keylen, *aa = a, *bb = b;

    if (aa == NULL || bb == NULL) return -2;       // need real keys
    keylen = IPT_KEYLEN(aa);
    if (keylen != IPT_KEYLEN(bb)) return -2;       // different AF_families
    if (keylen < 2) return -2;                     // need key bits to compare

    for(; --keylen > 0 && *aa==*bb; aa++, bb++)
        ;

    if (*aa < *bb) return -1;
    if (*aa > *bb) return 1;
    return 0;
}

/* ### `key_isin`
 * ```c
 *   int key_isin(void *a, void *b, void *m);
 * ```
 * return 1 iff a/m includes b, 0 otherwise
 * note:
 * - also means b/m includes a
 * - any radix keys/masks may have short(er) KEYLEN's than usual
 */

int
key_isin(void *a, void *b, void *m)
{
    uint8_t *aa = a, *bb = b, *mm = m;
    int matchlen = 0;  // how many bytes to match depends on mask

    // sanity checks
    if(aa == NULL || bb == NULL) return 0;

    // if((matchlen = IPT_KEYLEN(aa)) != IPT_KEYLEN(bb)) return 0;
    matchlen = min(IPT_KEYLEN(aa), IPT_KEYLEN(bb));
    matchlen = mm ? min(matchlen, IPT_KEYLEN(mm)) : matchlen;
    mm = mm ? mm+1 : max_mask;

    aa++; bb++;
    for (; --matchlen > 0; aa++, bb++, mm++)
        if ((*aa ^ *bb) & *mm) return 0;

    return 1;
}

/* ## radix node functions
 */

/* ### _dumprn`
 * ```c
 *   void _dumprn(const char *s, struct radix_node *rn);
 * ```
 * dump radix node characteristics to stderr
 */

void _dumprn(const char *s, struct radix_node *rn)
{
    char dbuf[MAX_STRKEY];
    fprintf(stderr, "%10s rn @ %p", s, (void*)rn);
    if(rn!=NULL) {
        if(RDX_ISLEAF(rn)) {
            fprintf(stderr, " %s", key_tostr(dbuf, rn->rn_key));
            fprintf(stderr, "/%d", key_masklen(rn->rn_mask));
            fprintf(stderr, ", keylen %d", IPT_KEYLEN(rn->rn_key));
        }
        fprintf(stderr, ", isroot %d", rn->rn_flags & RNF_ROOT);
        fprintf(stderr, ", isleaf %d", RDX_ISLEAF(rn));
        fprintf(stderr, ", isNORM %d", rn->rn_flags & RNF_NORMAL);
        fprintf(stderr, ", flags  %d", rn->rn_flags);
        fprintf(stderr, ", rn_bit %d", rn->rn_bit);
    }
    fprintf(stderr, "\n");
}

/* ### `rdx_flush`
 * ```c
 *   int rdx_flush(struct radix_node *rn, void *args);
 * ```
 * free user controlled resources.
 *
 * Called by walktree, rdx_flush:
 * - frees the key and, if applicable,
 * - uses the purge function to allow user controlled resources to be freed.
 * The purge function is supplied at tree creation time.
 *
 * Note: rdx_flush is called from walktree and only on _LEAF_ nodes, so the rn
 * pointer is cast to pointer to entry_t.  As a walktree_f_t, it always returns
 * the value 0 to indicate success, otherwise the walkabout would stop.
 */

int
rdx_flush(struct radix_node *rn, void *args)
{
    struct entry_t *entry = NULL;
    purge_t *arg = NULL;
    struct radix_node_head *rnh = NULL;

    if (rn == NULL) return 0;
    if (args == NULL) return 0;  /* need args for head pointer */

    arg = (purge_t *)args;
    rnh = arg->head;

    /* remove entry [rn[2], ptr] from the tree */
    entry = (entry_t *)rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, &rnh->rh);

    if (entry == NULL) return 0;

    /* invalidate the entry before it's freed */
    *entry->rn[0].rn_key = -1;  /* illegal KEYLEN */
    free(entry->rn[0].rn_key);
    /* entry->rn[0].rn_key = NULL; */

    if (entry->value != NULL && arg->purge != NULL)
        arg->purge(arg->args, &entry->value);

    free(entry);

    return 0;
}

/* ### `rdx_firstleaf`
 * ```c
 *   struct radix_node *rdx_firstleaf(struct radix_head *rh);
 * ```
 * Find first non-ROOT leaf of in the prefix or mask tree
 * Return NULL if none found.
 *
 * Note: the /0 mask is never stored in the mask tree even if stored explicitly
 * using prefix/0.  Hence, the /0 mask won't be found by this function.
 */

struct radix_node *
rdx_firstleaf(struct radix_head *rh)
{
    // find first leaf in tree
    struct radix_node *rn = NULL;

    if (rh == NULL) return NULL;

    /* goto treetop's left */
    rn = rh->rnh_treetop->rn_left;
    while(! RDX_ISLEAF(rn))
        rn = rn->rn_left;

    /* if 1 or more 0/msk's were inserted, return the first one */
    if(rn->rn_dupedkey)
        return rn->rn_dupedkey;

    /* otherwise, go up & right and then go straight left */
    rn = rn->rn_parent->rn_right;
    while(!RDX_ISLEAF(rn))
        rn = rn->rn_left;

    /* if now at right-end marker, it may have a dupedkey (max 1),
     * if not we're done anyway since the tree is empty otherwise */
    if(RDX_ISROOT(rn) && RDX_ISLEAF(rn))
        rn = rn->rn_dupedkey;

    return rn;
}

/* ### `rdx_nxtleaf`
 * ```c
 *   struct radix_node *rdx_nextleaf(struct radix_node *rn);
 * ```
 * Given a radix_node (INTERNAL or LEAF), find the next leaf in the tree. Note
 * that the caller must check the IPTF_DELETE flag herself.  Reason is to allow
 * upper logic to be performed across both deleted and normal leafs, such as
 * actually deleting the flagged nodes..
 */

struct radix_node *
rdx_nextleaf(struct radix_node *rn)
{
    /* given a node, find next leaf */

    if (rn == NULL) return NULL;        /* already done */

    /* if rn is an INTERNAL node, return its first left leaf */
    if (! RDX_ISLEAF(rn)) {
        while(!RDX_ISLEAF(rn))
          rn = rn->rn_left;
        return rn;
    }

    /*
     * Edge case: the right-end marker may have a dupedkey.
     *
     * The right-end marker is the only (root)leaf with a keylen of 255 since
     * the key, including its keylen byte, is all-ones.  It takes a full mask
     * to create a 'normal' leaf with the all-broadcast address, hence the
     * right-end marker root-leaf can have at most 1 dupedkey child since masks
     * are always applied to keys prior to storing them in the tree.
     */

    if(RDX_ISLEAF(rn->rn_parent)
            && RDX_ISROOT(rn->rn_parent)
            && 0xff == (0xff & IPT_KEYLEN(rn->rn_parent->rn_key))) {
        return NULL; /* we were RE-marker dupedkey child */
    }

    /* return the next (less specific) dupedkey, if any */
    if (RDX_ISLEAF(rn) && rn->rn_dupedkey)
        return rn->rn_dupedkey;

    /* go back to start of dupedkey-chain */
    while(RDX_ISLEAF(rn->rn_parent))
        rn = rn->rn_parent;

    /* go up while rn is a right child */
    while(!RDX_ISLEAF(rn->rn_parent) && RDX_ISRCHILD(rn))
        rn = rn->rn_parent;

    /* go up&right, then straight left */
    for(rn = rn->rn_parent->rn_right; !RDX_ISLEAF(rn);)
      rn = rn->rn_left;

    /* if at RightEnd-marker, return dupedkey if any */
    if (rn && RDX_ISROOT(rn) && RDX_ISLEAF(rn))
        rn = rn->rn_dupedkey;

    return rn;
}

/* ### `pairleaf`
 * ```c
 *   struct radix_node *pairleaf(struct radix_node *oth);
 * ```
 * Find and return the leaf whose key forms a pair with the given leaf
 * node such that both fit in an enclosing supernet with the given leaf's
 * masklength-1.
 * Note:
 * - 0/0 is the 'ultimate' supernet which combines 0.0.0.0/1 and 128.0.0.0/1
 */

struct radix_node *
rdx_pairleaf(struct radix_node *oth) {
    uint8_t pair[MAX_BINKEY];
    struct radix_node *rn;
    int maxb;

    /* oth must be a valid, non-deleted LEAF */
    if(oth == NULL || (oth->rn_flags & IPTF_DELETE)) return NULL;
    if(! RDX_ISLEAF(oth)) return NULL;
    if(! key_bypair(pair, oth->rn_key, oth->rn_mask)) return NULL;

    /* goto up the tree to the governing internal node */
    maxb = IPT_KEYOFFSET + key_masklen(oth->rn_mask);
    for(rn = oth; RDX_ISLEAF(rn) || rn->rn_bit >= maxb; rn = rn->rn_parent)
      ;

    /* descend following pair-key */
    while(! RDX_ISLEAF(rn))
      if (pair[rn->rn_offset] & rn->rn_bmask)
        rn = rn->rn_right;
      else
        rn = rn->rn_left;

    /* Never use ROOT-leafs for key comparisons (KEYLEN), take its dupedkey */
    if(RDX_ISROOT(rn)) rn = rn->rn_dupedkey;

    if (rn == NULL) return NULL;

    /* check key actually matches */
    if(key_cmp(pair, rn->rn_key) != 0)
      return NULL;

    /* return the leaf with the same mask length */
    while( rn && rn->rn_bit != oth->rn_bit)
      rn = rn->rn_dupedkey;

    /* check there was a leaf with the same mask length */
    /* _dumprn("leaf with same mask length", rn); */
    if (rn == NULL) return NULL;

    /* cannot return an inactive, deleted prefix */
    if (rn->rn_flags & IPTF_DELETE)
        return NULL;

    return rn;
}

/* ### `rdx_firstnode`
 * ```c
 *   int rdx_firstnode(table_t *t, int af_fam);
 * ```
 * initialize the stack with the radix head nodes
 */

int
rdx_firstnode(table_t *t, int af_fam)
{

    while (t->top) tbl_stackpop(t);  /* clear the stack */

    if(af_fam == AF_INET)
        tbl_stackpush(t, TRDX_NODE_HEAD, t->head4);
    else if(af_fam == AF_INET6)
        tbl_stackpush(t, TRDX_NODE_HEAD, t->head6);
    else
        return 0; /* unknown af_family */

    return 1;
}

/* ### `rdx_nextnode`
 * ```c
 *   int rdx_nextnode(table_t *t, int *type, void **ptr);
 * ```
 * pop top and set type & node, push its progeny
 * - stackpush will ignore NULL pointers, so its safe to push those
 * return 1 on success with type,ptr set
 * return 0 on failure (eg stack exhausted or unknown type)
 */
int
rdx_nextnode(table_t *t, int *type, void **ptr)
{

    *ptr = NULL;
    *type = TRDX_NONE;

    // node types used
    struct radix_node_head *rnh = NULL;
    struct radix_node *rn = NULL;
    struct radix_mask_head *rmh = NULL;
    struct radix_mask *rm = NULL;

    if (t->top == NULL) return 0;  // no more work to be done

    // set return values
    *type = t->top->type;
    *ptr = t->top->elm;

    tbl_stackpop(t);

    // ensure popped node's progeny will be next
    switch (*type) {

        case TRDX_NODE_HEAD:
            rnh = *ptr;
            tbl_stackpush(t, TRDX_MASK_HEAD, rnh->rh.rnh_masks);

            // rnh_nodes[0] and [2] are LEAF nodes
            tbl_stackpush(t, TRDX_NODE, rnh->rnh_nodes[0].rn_dupedkey);
            tbl_stackpush(t, TRDX_NODE, rnh->rnh_nodes[2].rn_dupedkey);

            // rnh_nodes[1] aka treetop is an INTERNAL node
            rn = &rnh->rnh_nodes[1];
            // never push ROOT radix nodes
            if (! RDX_ISROOT(rn->rn_right))
                tbl_stackpush(t, TRDX_NODE, rn->rn_right);
            if (! RDX_ISROOT(rn->rn_left))
                tbl_stackpush(t, TRDX_NODE, rn->rn_left);
            tbl_stackpush(t, TRDX_MASK, rn->rn_mklist);
            break;

        case TRDX_NODE:
            rn = *ptr;
            if (RDX_ISLEAF(rn)) {
                tbl_stackpush(t, TRDX_NODE, rn->rn_dupedkey);
            } else {
                tbl_stackpush(t, TRDX_MASK, rn->rn_mklist);
                // never push ROOT radix nodes
                if (! RDX_ISROOT(rn->rn_right))
                    tbl_stackpush(t, TRDX_NODE, rn->rn_right);
                if (! RDX_ISROOT(rn->rn_left))
                    tbl_stackpush(t, TRDX_NODE, rn->rn_left);
            }
            break;

        case TRDX_MASK_HEAD:
            rmh = *ptr;
            tbl_stackpush(t, TRDX_MASK_HEAD, rmh->head.rnh_masks);
            rn = &rmh->mask_nodes[1]; // aka treetop
            // never push ROOT radix nodes
            if (! RDX_ISROOT(rn->rn_right))
                tbl_stackpush(t, TRDX_NODE, rn->rn_right);
            if (! RDX_ISROOT(rn->rn_left))
                tbl_stackpush(t, TRDX_NODE, rn->rn_left);
            break;

        case TRDX_MASK:
            rm = *ptr;
            tbl_stackpush(t, TRDX_MASK, rm->rm_mklist);
            break;

        default: return 0;
    }

    return 1;
}

/* ## table functions
 */

/* ### `tbl_create`
 * ```c
 *   table_t *tbl_create(purge_f_t *fp):
 * ```
 * Create a new iptable with 2 radix trees.
 */

table_t *
tbl_create(purge_f_t *fp)
{
    table_t *tbl = NULL;

    /* calloc so all ptrs & counters are set to NULL/zero */
    tbl = calloc(sizeof(*tbl), 1);
    if (tbl == NULL) return NULL;

    if (rn_inithead((void **)&tbl->head4, 8) == 0) {
        free(tbl);
        return NULL;
    }
    if (rn_inithead((void **)&tbl->head6, 8) == 0) {
        rn_detachhead((void **)&tbl->head4);
        free(tbl);
        return NULL;
    }

    tbl->purge = fp;

    return tbl;
}

/* ### `tbl_walk`
 * ```c
 *   int tbl_walk(table_t *t, walktree_f_t *f, void *fargs);
 * ```
 * run f(args, leaf) on leafs in IPv4 tree and IPv6 tree
 */
int
tbl_walk(table_t *t, walktree_f_t *f, void *fargs)
{
    if (t == NULL) return 0;
    t->head4->rnh_walktree(&t->head4->rh, f, fargs);
    t->head6->rnh_walktree(&t->head6->rh, f, fargs);

   return 1;
}

/* ### `tbl_destroy`
 * ```c
 *   int tbl_destroy(table_t **t, void *pargs);
 * ```
 * Destroy table, free all resources owned by table and user
 * - return 1 on success, 0 on failure
 */

int
tbl_destroy(table_t **t, void *pargs)
{
    purge_t args;  // args to flush radix nodes & free userdata

    if (t == NULL || *t == NULL) return 0;  // nothing to free

    // pickup user purge callback & its contextual args
    args.purge = (*t)->purge;
    args.args = pargs;

    // clear ipv4 table
    args.head = (*t)->head4;
    (*t)->head4->rnh_walktree(&(*t)->head4->rh, rdx_flush, &args);

    /* walktree misses out on RightEnd-marker's dupedkey, of which it can 
     * have only 1
     * */
    if((*t)->head4->rnh_nodes[2].rn_dupedkey)
        rdx_flush((*t)->head4->rnh_nodes[2].rn_dupedkey, &args);

    rn_detachhead((void **)&(*t)->head4);

    // clear ipv6 table
    args.head = (*t)->head6;
    (*t)->head6->rnh_walktree(&(*t)->head6->rh, rdx_flush, &args);

    /* walktree misses RightEnd-marker's dupedkey */
    if ((*t)->head6->rnh_nodes[2].rn_dupedkey)
        rdx_flush(((*t)->head6->rnh_nodes)[2].rn_dupedkey, &args);
    rn_detachhead((void **)&(*t)->head6);

    // clear the stack
    while ((*t)->top != NULL) tbl_stackpop(*t);

    free(*t);
    *t = NULL;

    return 1;
}

/* ### `tbl_get`
 * ```c
 *   entry_t *tbl_get(table_t *t, const char *s);
 * ```
 * Get an exact match for addr/mask prefix.
 */

entry_t *
tbl_get(table_t *t, const char *s)
{
    // An exact lookup for addr/mask, missing mask is set to AF's max mask
    // uint8_t *addr = NULL;
    uint8_t addr[MAX_BINKEY];
    uint8_t mask[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;
    struct radix_node_head *head = NULL;
    entry_t *e = NULL;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return NULL;
    if (! key_bystr(addr, &mlen, &af, s)) return NULL;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return NULL;

    if (! key_bylen(mask, mlen, af)) return NULL;
    if (! key_network(addr, mask)) return NULL;

    e = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match

    /* itr_gc, node deleted but not yet gc'd */
    if (e && (e->rn->rn_flags & IPTF_DELETE))
        return NULL;

    return e;
}

/* ### `tbl_set`
 * ```c
 *   int tbl_set(table_t *t, const char *s, void *v, void *pargs);
 * ```
 */

int
tbl_set(table_t *t, const char *s, void *v, void *pargs)
{
    // A missing mask is taken to mean AF's max mask
    // - applies mask before searching/setting the tree
    /* uint8_t *addr = NULL; */

    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], *treekey = NULL;
    int mlen = -1, af = AF_UNSPEC;
    entry_t *e = NULL;
    struct radix_node *rn = NULL;
    struct radix_node_head *head = NULL;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return 0;
    if (! key_bystr(addr, &mlen, &af, s)) return 0;
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_network(addr, mask)) return 0;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return 0;

    e = (entry_t *)head->rnh_lookup(addr, mask, &head->rh); // exact match
    if (e) {
        /* purge called to free userdata */
        if(e->value && t->purge)
            t->purge(pargs, &e->value);
        e->value = v;

        /* no need to update stats if e was not flagged as deleted */
        if((e->rn->rn_flags & IPTF_DELETE) == 0)
            return 1;

        e->rn->rn_flags &= ~IPTF_DELETE;  // clear delete flag

    } else {
        // add new entry, need to donate a new key for the tree to keep
        if (!(e = calloc(sizeof(* e),1))) return 0;
        e->value = v;
        treekey = key_copy(addr);

        rn = head->rnh_addaddr(treekey, mask, &head->rh, e->rn);
        if (!rn) {
            if (t->purge)
                t->purge(pargs, &e->value);
            free(e);
            free(treekey); // t'was not stored
            return 0;
        }

    }

    if (af == AF_INET) t->count4++;
    else t->count6++;

    return 1;
}

/* ### `tbl_del`
 * ```c
 *   int tbl_del(table_t *t, const char *s, void *pargs);
 * ```
 */

int
tbl_del(table_t *t, const char *s, void *pargs)
{
    // Deletion requires exact match on prefix
    // - a missing mask is set to AF's max mask
    entry_t *e;
    struct radix_node_head *head = NULL;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;

    // get head, af, addr, mask, or bail on error
    if (t == NULL || s == NULL) return 0;
    if (! key_bystr(addr, &mlen, &af, s)) return 0;
    if (! key_bylen(mask, mlen, af)) return 0;
    if (! key_network(addr, mask)) return 0;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return 0;

    if (t->itr_lock) {
        /* active iterator(s), so flag node (if any & needed) for DELETION */
        e = (entry_t *)head->rnh_lookup(addr, mask, &head->rh);
        if (!e || (e->rn->rn_flags & IPTF_DELETE)) return 0;
        e->rn->rn_flags |= IPTF_DELETE;
        /* fprintf(stderr, "flagged %s", s); */

    } else {
        e = (entry_t *)head->rnh_deladdr(addr, mask, &head->rh);
        if (!e) return 0;
        free(e->rn[0].rn_key);                      // free the key
        if(e->value != NULL && t->purge != NULL)
            t->purge(pargs, &e->value);             // free the user data
        free(e);                                    // free the entry
    }

    /* if we get here, a non-deleted node was found, so decrement counter */
    if (af == AF_INET) t->count4--;
    else t->count6--;

    return 1;
}

/* ### `tbl_lpm`
 * ```c
 *   entry_t *tbl_lpm(table_t *t, const char *s);
 * ```
 */

entry_t *
tbl_lpm(table_t *t, const char *s)
{
    // longest prefix match for address (a /mask is ignored)
    struct radix_node_head *head = NULL;
    uint8_t addr[MAX_BINKEY];
    int mlen = -1, af = AF_UNSPEC;
    struct radix_node *rn;
    entry_t *e = NULL; /* defaults to no match found */

    if (t == NULL || s == NULL) return NULL;
    if (! key_bystr(addr, &mlen, &af, s)) return NULL;

    if (af == AF_INET) head = t->head4;
    else if (af == AF_INET6) head = t->head6;
    else return NULL;

    /* rn will be the longest prefix match (if any) */
    rn = head->rnh_matchaddr(addr, &head->rh);

    /* cannot return rn if it was flagged for deletion */
    while(rn && (rn->rn_flags & IPTF_DELETE))
        rn = tbl_lsm(rn);

    e = rn ? (entry_t *)rn : NULL;

    return e;
}

/* ### `tbl_lsm`
 * ```c
 *   struct radix_node *tbl_lsm(struct radix_node *rn);
 * ```
 * Given a leaf, find a less specific leaf or fail
 * - used by tbl_lpm in case the match is flagged for deletion
 */

struct radix_node *
tbl_lsm(struct radix_node *rn)
{
    /* less specific match for rn'n address and masklength */
    struct radix_node *org_rn;
    int rn_bit = rn->rn_bit;

    if (rn == NULL) return NULL;
    /* candidates are checked against rn's key, so it MUST be a leaf */
    if (!RDX_ISLEAF(rn)) return NULL;

    /* search less specific entries in dupedkey chain, if any */
    for(org_rn = rn; rn; rn = rn->rn_dupedkey)
        if ((rn->rn_flags & RNF_NORMAL)
            && rn_bit < rn->rn_bit)
            return rn;

    /* go to parent of dupedchain */
    for (rn = org_rn; RDX_ISLEAF(rn);)
        rn = rn->rn_parent;

    /* go up the tree */
    do {

        struct radix_mask *m;
        rn = rn->rn_parent;
        m = rn->rn_mklist;
        struct radix_node *x = rn;
        while (m) {
            if (m->rm_flags & RNF_NORMAL) {
                if (rn_bit <= m->rm_bit && !(m->rm_leaf->rn_flags & IPTF_DELETE))
                    return (m->rm_leaf);
            } else {
                // off = min(rn->rn_offset, matched_off);
                // x = rn_search_m(v, rn, m->rm_mask);
                /* search w/ mask */
                for(; x->rn_bit >= 0;) {
                    if((x->rn_bmask & m->rm_mask[x->rn_offset]) &&
                       (x->rn_bmask & org_rn->rn_key[x->rn_offset]))
                        x = x->rn_right;
                    else
                        x = x->rn_left;
                }
                while (x && x->rn_mask != m->rm_mask)
                    x = x->rn_dupedkey;
                //if (x && rn_satisfies_leaf(v, x, off))
                //    return (x);
                if (x && key_isin(org_rn->rn_key, x->rn_key, x->rn_mask))
                    return x;
            }
            m = m->rm_mklist;
        }

    } while (rn && (rn != rn->rn_parent) && !(rn->rn_flags & RNF_ROOT)); /* treetop */

    return NULL;
}

/* ### `tbl_stackpush`
 * ```c
 *   int tbl_stackpush(table_t *t, int type, void *elm);
 * ```
 */

int
tbl_stackpush(table_t *t, int type, void *elm)
{
    // insert element into stack
    stackElm_t *node = NULL;

    if (t == NULL) return 0;     /* no table, no stack */
    if (elm == NULL) return 0;   /* ignore NULL elements */

    node = calloc(1, sizeof(stackElm_t));

    if (! node) return 0;

    node->type = type;
    node->elm = elm;
    node->next = t->top;
    t->top = node;
    t->size += 1;

    return 1;
}

/* ### `tbl_stackpop`
 * ```c
 *   int tbl_stackpop(table_t *t);
 * ```
 */

int
tbl_stackpop(table_t *t)
{
    // pop & free top element
    stackElm_t *node;

    if (t == NULL) return 0;       /* no table, no stack */
    if (t->top == NULL) return 0;  /* no stack, no pop */

    node = t->top;
    t->top = node->next;
    free(node);

    t->size -= 1;
    if(t->top == NULL)  /* just in case somebody messed with the size */
        t->size = 0;

    return 1;
}
