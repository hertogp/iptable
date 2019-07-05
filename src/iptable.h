// file iptable.h

#ifndef iptable_h
#define iptable_h

typedef struct entry_t {
    struct radix_node rn[2];        // leaf & internal radix nodes
    void *value;                    // user data, freed by purge_f_t callback
} entry_t;

typedef void purge_f_t(void *, void **); // user callback to free value

typedef struct purge_t {            // args for rdx_flush
   struct radix_node_head *head;    // head of tree where rdx_flush operates
   purge_f_t *purge;                // the callback to free entry->value
   void *args;                      // extra args for the callback
} purge_t;

typedef struct stackElm_t {
    int type;
    void * elm;
    struct stackElm_t *next;
} stackElm_t;

typedef struct table_t {
    struct radix_node_head *head4;  // IPv4 radix tree
    struct radix_node_head *head6;  // IPv6 radix tree

    size_t count4;
    size_t count6;

    purge_f_t *purge;               // callback to free userdata

    stackElm_t *top;
    size_t size;
} table_t;

#define IPT_KEYOFFSET 8             // 8 bit offset to 1st byte of key
#define IPT_KEYLEN(k) (*k)          // 1st byte is 5 or 17 (includes itself)
#define IPT_KEYPTR(k) (k+1)         // 2nd byte starts actual key

#define IP4_KEYLEN 4
#define IP4_MAXMASK 32
#define IP4_PFXSTRLEN (INET_ADDRSTRLEN + 3)   // + /32

#define IP6_KEYLEN 16
#define IP6_MAXMASK 128
#define IP6_PFXSTRLEN (INET6_ADDRSTRLEN + 4)  // + /128

#define STR_IS_IP4(s) (strchr(s, (int)'.') ? 1 : 0)  // not for shorthand ipv4
#define STR_IS_IP6(s) (strchr(s, (int)':') ? 1 : 0)

#define KEY_IS_IP4(k) (*((uint8_t *)(k))==(1+IP4_KEYLEN))
#define KEY_IS_IP6(k) (*((uint8_t *)(k))==(1+IP6_KEYLEN))
#define KEY_AF_FAM(k) \
    (KEY_IS_IP4(k) ? AF_INET : KEY_IS_IP6(k) ? AF_INET6 : AF_UNSPEC)

// binary key buffer = [LEN-byte IP6_KEYLEN] = 1 + 16 = 17
#define MAX_BINKEY (1 + IP6_KEYLEN)
// max size for string key (fits IP6 with /mask)
#define MAX_STRKEY IP6_PFXSTRLEN
// exact KEYBUF length by FAM
#define FAM_KEYLEN(af) (af==AF_INET ? (uint8_t)(1+IP4_KEYLEN) \
        : af==AF_INET6 ? (uint8_t)(1+IP6_KEYLEN) : 0x00)
#define AF_UNKNOWN(f) (f != AF_INET && f!= AF_INET6)

// radix tree macros
#define RDX_ISLEAF(rn) (rn->rn_bit < 0)
#define RDX_ISROOT(rn) (rn->rn_flags & RNF_ROOT)
#define MSK_ISROOT(rm) (rm->rm_flags & RNF_ROOT)
#define RDX_ISRIGHT_CHILD(rn) (rn->rn_parent->rn_right == rn)

// used to interpolate the value of CONST into string: "%"STRINGIFY(x)"s"
#define STRINGIFY(x) STRINGIFY_x(x)
#define STRINGIFY_x(x) #x

// RADIX node types
// - note: radix_head is actually struct inside radix_node_head and not a
//   'node' itself.  TODO: eleminate this as a 'node type'?
#define TRDX_NONE -1
#define TRDX_NODE_HEAD 0
#define TRDX_HEAD 1
#define TRDX_NODE 2
#define TRDX_MASK_HEAD 3
#define TRDX_MASK 4

// IPT supported AF FAMILY's
enum IPT_PROTOS {
    IPT_UNSPEC = 0,
    IPT_INET   = 1,
    IPT_INET6  = 2,
    IPT_MAX    = 4
} IPT_PROTOS;
#define IPT_VALID_PROTO(x) ((x) > IPT_UNSPEC && (x) < IPT_MAX)

// taken from radix.c
#define min(a, b) ((a) < (b) ? (a) : (b))
#define RDX_MAX_KEYLEN    32

// -- PROTOTYPES

void _dumprn(const char *s, struct radix_node *rn);

// -- key funcs

uint8_t *key_alloc(int);
uint8_t *key_copy(uint8_t *);

uint8_t *key_bystr(uint8_t *, int *, int *, const char *);
uint8_t *key_bylen(uint8_t *, int, int);
const char *key_tostr(void *, char *);
int key_tolen(void *);
int key_incr(void *);
int key_decr(void *);
int key_cmp(void *, void *);
int key_isin(void *, void *, void *);
int key_network(void *, void *);
int key_broadcast(void *, void *);
int key_invert(void *);

// -- rdx funcs

int rdx_flush(struct radix_node *, void *);
struct radix_node *rdx_firstleaf(struct radix_head *);
struct radix_node *rdx_nextleaf(struct radix_node *);
int rdx_firstnode(table_t *, int);
int rdx_nextnode(table_t *, int *, void **);

// -- tbl funcs

table_t *tbl_create(purge_f_t *);
entry_t *tbl_get(table_t *, const char *);
entry_t *tbl_lpm(table_t *, const char *);
entry_t *tbl_lsm(table_t *, const char *);
int tbl_set(table_t *, const char *, void *, void *);
int tbl_del(table_t *, const char *, void *);
int tbl_walk(table_t *, walktree_f_t *, void *);
int tbl_destroy(table_t **, void *);
int tbl_less(table_t *, const char *, int, walktree_f_t *, void *);
int tbl_more(table_t *, const char *, int, walktree_f_t *, void *);
int tbl_stackpush(table_t *, int, void *);
int tbl_stackpop(table_t *);


#endif
