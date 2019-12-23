/* ---
 * title: iptable reference
 * author: hertogp
 * tags: C api lua radix trie
 * ...
 *
 * Wrapper for radix.c by the FreeBSD project.
 *
 */

#ifndef iptable_h
#define iptable_h

/* # iptable.h
 *
 * ## `#define's`
 *
 * ### IPT_x
 * `IPT_KEYOFFSET`
 * : the offset to the actual key in the byte array
 *
 * `IPT_KEYLEN(k)`
 * : the length of byte array `k`
 *
 * `IPT_KEYPTR(k)`
 * : pointer to the location of the key in the byte array `k`
 */

#define IPT_KEYOFFSET 8             // 8 bit offset to 1st byte of key
#define IPT_KEYLEN(k) (*k)          // 1st byte is 5 or 17 (includes itself)
#define IPT_KEYPTR(k) (k+1)         // 2nd byte starts actual key

/* ### IP4_x
 * `IP4_KEYLEN`
 * : the length of the byte array to hold an IPv4 binary key
 *
 * `IP4_MAXMASK`
 * : the maximum number of bits in an IPv4 binary mask
 *
 * `IP4_PFXSTRLEN`
 * : buffer size for an ipv4 prefix string (addr/len)
 */

#define IP4_KEYLEN 5
#define IP4_MAXMASK 32
#define IP4_PFXSTRLEN (INET_ADDRSTRLEN + 3)   // + /32

/* ### IP6_x
 * `IP6_KEYLEN`
 * : the length of the byte array to hold an IPv6 binary key
 *
 * `IP6_MAXMASK`
 * : the maximum number of bits in an IPv6 binary mask
 *
 * `IP6_PFXSTRLEN`
 * : buffer size for an ipv6 prefix string (addr/len)
 */

#define IP6_KEYLEN 17
#define IP6_MAXMASK 128
#define IP6_PFXSTRLEN (INET6_ADDRSTRLEN + 4)  // + /128

/* ### STR_x
 * `STR_IS_IP4(s)`
 * : detects an ipv4 address by an in-string '.'-character
 *
 * `STR_IS_IP6(s)`
 * : detects an ipv6 address by an in-string ':'-character
 */

#define STR_IS_IP4(s) (strchr(s, (int)'.') ? 1 : 0)
#define STR_IS_IP6(s) (strchr(s, (int)':') ? 1 : 0)

/* ### KEY_x
 * `KEY_IS_IP4(k)`
 * : checks for an ipv4 binary key by checking the byte array's length
 *
 * `KEY_IS_IP6(k)`
 * : checks for an ipv6 binary key by checking the byte array's length
 *
 * `KEY_AF_FAM(k)`
 * : returns `AF_INET(6)` or `AF_UNSPEC` based on binary key length
 *
 * `KEY_LEN_FAM(af)`
 * : returns byte array lengh for given AF family.
 */

#define KEY_IS_IP4(k) (*((uint8_t *)(k))==(IP4_KEYLEN))
#define KEY_IS_IP6(k) (*((uint8_t *)(k))==(IP6_KEYLEN))
#define KEY_AF_FAM(k) \
    (KEY_IS_IP4(k) ? AF_INET : KEY_IS_IP6(k) ? AF_INET6 : AF_UNSPEC)
#define KEY_LEN_FAM(af) (af==AF_INET ? (uint8_t)(IP4_KEYLEN) \
        : af==AF_INET6 ? (uint8_t)(IP6_KEYLEN) : 0x00)

/* ### MAX_x
 * `MAX_BINKEY`
 * : buffer size to hold both ipv4/ipv6 binary keys
 *
 * `MAX_STRKEY`
 * : buffer size to hold both ipv4/ipv6 prefix/len strings
 */

#define MAX_BINKEY IP6_KEYLEN
#define MAX_STRKEY IP6_PFXSTRLEN

/* ### AF_x
 * `AF_UNKNOWN(f)`
 * : true if f is not AF_INET or AF_INET6
 */

#define AF_UNKNOWN(f) (f != AF_INET && f!= AF_INET6)

/* ### RDX_x
 * `RDX_ISLEAF(rn)`
 * : true if radix node `rn` is a LEAF node
 *
 * `RDX_ISINTERNAL(rn)`
 * : true if radix node `rn` is an INTERNAL node
 *
 * `RDX_ISROOT(rn)`
 * : true if radix node `rn` is a ROOT node (LE-mark, TOP, RE-mark)
 *
 * `MSK_ISROOT(rm)`
 * : true if radix mask node `rm` is a ROOT node (LE,TOP,RE)
 *
 * `RDX_ISRCHILD(rn)`
 * : true if radix node `rn` is its parent right child
 *
 * `RDX_MAX_KEYLEN`
 * : the maximum length for a byte array.
 */

// radix tree macros
#define RDX_ISLEAF(rn) (rn->rn_bit < 0)
#define RDX_ISINTERNAL(rn) (rn->rn_bit >= 0)
#define RDX_ISROOT(rn) (rn->rn_flags & RNF_ROOT)
#define MSK_ISROOT(rm) (rm->rm_flags & RNF_ROOT)
#define RDX_ISRCHILD(rn) (rn->rn_parent->rn_right == rn)
#define RDX_MAX_KEYLEN    32

/* ### RDX FLAG
 * `IPTF_DELETE`
 * : additional radix node flag to indicate node was deleted
 *
 * When an iteration is happening, radix nodes are flagged for deletion rather
 * than being removed immediately.  All iterators run with an upvalue that has
 * a garbage collector which will eventually remove radix nodes flagged for
 * deletion when it is safe to do so.
 *
 * The flag is set in `rn_flags` in a radix node, alongside the flags
 * defined by `radix.h`
 */

#define IPTF_DELETE 8

/* ### RDX node types
 * A table has a stack which allows for pushing arbitrary data combined with a
 * type identifier for that data.  The stack is only used by the radix iterator
 * which is read only and allows for graphing a radix tree.  See 'ipt2dot.lua`
 *
 * Radix node type include:
 * - `TRDX_NONE` -- indicates an unknown type
 * - `TRDX_NODE_HEAD` -- a radix_node_head
 * - `TRDX_HEAD` -- a radix head, a struct inside a radix node head
 * - `TRDX_NODE' -- a single radix node
 * - `TRDX_MASK_HEAD` -- the head of the mask tree
 * - `TRDX_MASK` -- a radix mask node
 */


#define TRDX_NONE -1
#define TRDX_NODE_HEAD 0
#define TRDX_HEAD 1
#define TRDX_NODE 2
#define TRDX_MASK_HEAD 3
#define TRDX_MASK 4

// taken from radix.c
#define min(a, b) ((a) < (b) ? (a) : (b))

/* ## Structures
 */

/*
 * ### `entry_t`
 * The type `entry_t` has 2 members:
 *
 * - `rn[2]`, an array of two radix nodes: a leaf & an internal node.
 * - `void *value`, which points to user data.
 *
 * The radix tree stores/retrieves pointers to `radix leaf nodes` using binary
 * keys. So a user data structure must begin with an array of two radix nodes:
 * a leaf node for storing the binary key, associated with the user data, and
 * an internal node to actually insert the leaf node into the tree.
 *
 * Retrieving the data is done by matching, either exact or using a longest
 * prefix match,  againts a binary key which yields a pointer to a leaf node.
 * That pointer is then recast to `entry_t *` in order to access the user data
 * associated with the matched binary key in the tree via the `value` pointer.
 *
 */

typedef struct entry_t {
    struct radix_node rn[2];        // leaf & internal radix nodes
    void *value;                    // user data, freed by purge_f_t callback
} entry_t;

/* ### `purge_t`
 * The type `purge_t` has the following members:
 *
 * - `struct radix_node_head *head`, the head of a radix tree
 * - `purge_f_t *purge`, a callback function pointer; to free user data
 * - `void *args`, an opague pointer to be interpreted by `purge`
 *
 * This structure is used to relay contextual arguments to the user callback
 * function upon deletion time.  The different levels of memory ownership
 * include:
 *
 * - `radix.c`, which owns:
 *      + the 'mask' tree completely, but
 *      + only the radix_node_head for the 'key'-tree, not the leafs
 * - `iptable.c`, which owns:
 *      + the radix nodes that are part of `entry_t`, and
 *      + the binary key which it derives from `const char *` strings
 * - `user.c`, she owns:
 *      + the memory pointed to by the `void *value` pointer in `entry_t`
 *
 * So when `user.c` calls `iptable.c`'s [`tbl_create`](### table_create), it
 * supplies a *purge* function whose signature is:
 * ```c
 *   typedef void purge_f_t(void *pargs, void *value);
 * ```
 * When `user.c` calls `iptable.c`'s [`tbl_del`](### tbl_del), it supplies the
 * prefix string to be deleted and a contextual argument for its `purge`
 * callback function (`pargs` here).  `tbl_del` then:
 *
 * - derives a binary from the prefix given
 * - calls `radix.c's rnh_deladdr` to remove the binary key,
 *   (if succesful, two radix nodes are returned (ie an `entry_t`))
 * - frees the `entry_t`'s memory and the binary key memory, and finally
 * - calls back the `purge` function supplying it with both the
 *     + `void *pargs`, the contextual argument for this deletion, and
 *     + `void *value`, from the `entry_t` that was deleted.
 *
 * It may seem a bit convoluted, but it allows the user's `purge` callback to
 * examine a request to free user memory in context.
 */

typedef void purge_f_t(void *, void **); // user callback to free value

typedef struct purge_t {            // args for rdx_flush
   struct radix_node_head *head;    // head of tree where rdx_flush operates
   purge_f_t *purge;                // the callback to free entry->value
   void *args;                      // extra args for the callback
} purge_t;

/* ### `stackElm_t`
 * A stack element has members:
 * - `int type`, denotes the type of this element
 * - `void *elm`, an opaque element pointer
 * - `struct stackElm_t *next`, pointer to the next stack element
 *
 * An iptable contains a stack, which is only used by `rdx_firstnode` and
 * `rdx_nextnode` to perform a preorder (node, left, right) traversal and node
 * processing of all nodes of all types of all trees used in the table.  I.e.
 * it traverses both the 'key'-tree as well as the 'mask'-tree and yields all
 * nodes of all types used in either tree.
 *
 * This makes it possible to produce a dot-file of a radix tree and create an
 * image using graphviz's dot tool.
 */

typedef struct stackElm_t {
    int type;
    void * elm;
    struct stackElm_t *next;
} stackElm_t;

/* ### `table_t`
 * An iptable has the following members:
 * - `struct radix_node_head *head4`, the head of the ipv4 radix tree
 * - `struct radix_node_head *head6`, the head of the ipv6 radix tree
 * - `size_t count4`, the number of ipv4 prefixes present in the ipv4 tree
 * - `size_t count6`, the number of ipv6 prefixes present in the ipv6 tree
 * - `purge_f_t *purge`, user callback for freeing user data
 * - `int itr_lock`, indicates the presence of active iterators
 * - `stackElm_t *top`, the stack to iterate across all radix nodes in all trees
 * - `size_t size`, the current size of the of the stack
 *
 * Two separate radix trees are used to store ipv4 resp. ipv6 binary keys.
 * Table operations detect the type of prefix used and access the corresponding
 * tree. Each time a prefix is added or deleted, the tree's counter is updated.
 * The `purge` function pointer is supplied upon tree creation time and is
 * called whenever user data can be freed, see [`purge_t`](### purge_t).
 *
 * The `itr_lock` is actually a Lua specific feature to track the presence of
 * any currently active tree iterators (there are a few).  This allows for
 * postponed radix node removal while some iterator is still traversing one of
 * the trees.
 *
 * Finally, the `*top` and `size` exist in order to be able to graph the
 * tree(s).
 *
 */

typedef struct table_t {
    struct radix_node_head *head4;  // IPv4 radix tree
    struct radix_node_head *head6;  // IPv6 radix tree
    size_t count4;
    size_t count6;
    purge_f_t *purge;               // callback to free userdata
    int itr_lock;                   // count of currently active iterators
    stackElm_t *top;                // only used to iterate across radix nodes
    size_t size;                    // number of elms on the stack
} table_t;


// -- PROTOTYPES

void _dumprn(const char *, struct radix_node *);

// -- key funcs

const char *key_tostr(char *, void *);
const char *key_tostr_full(char *, void *);
int key_broadcast(void *, void *);
int key_cmp(void *, void *);
int key_invert(void *);
int key_reverse(void *);
int key_isin(void *, void *, void *);
int key_masklen(void *);
int key_network(void *, void *);
uint8_t *key_byfit(uint8_t *m, uint8_t *a, uint8_t *b);
uint8_t *key_bylen(uint8_t *, int, int);
uint8_t *key_bynum(uint8_t *, size_t, int);
uint8_t *key_bypair(uint8_t *, const void *, const void *);
uint8_t *key_bystr(uint8_t *, int *, int *, const char *);
uint8_t *key_decr(uint8_t *, size_t);
uint8_t *key_incr(uint8_t *, size_t);

uint8_t *key_alloc(int);
uint8_t *key_copy(uint8_t *);


// -- rdx funcs

struct radix_node *rdx_firstleaf(struct radix_head *);
struct radix_node *rdx_nextleaf(struct radix_node *);
struct radix_node *rdx_pairleaf(struct radix_node *);
int rdx_firstnode(table_t *, int);
int rdx_nextnode(table_t *, int *, void **);

int rdx_flush(struct radix_node *, void *);

// -- tbl funcs

table_t *tbl_create(purge_f_t *);
entry_t *tbl_get(table_t *, const char *);
entry_t *tbl_lpm(table_t *, const char *);
struct radix_node *tbl_lsm(struct radix_node *);
int tbl_set(table_t *, const char *, void *, void *);
int tbl_del(table_t *, const char *, void *);
int tbl_destroy(table_t **, void *);

int tbl_walk(table_t *, walktree_f_t *, void *);
int tbl_stackpush(table_t *, int, void *);
int tbl_stackpop(table_t *);


#endif
