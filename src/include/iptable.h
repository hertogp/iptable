// file iptable.h

#ifndef iptable_h
#define iptable_h


typedef struct entry_t {
    struct radix_node rn[2];          // leaf & internal radix nodes
    void *value;                      // user data, free by purge_f_t callback
} entry_t;

typedef void purge_f_t(void *, void **);      // user supplied callback to free value

typedef struct purge_t {             // args for rdx_flush
   struct radix_node_head *head;            // head of tree where rdx_flush operates
   purge_f_t *purge;                  // the callback to free entry->value
   void *args;                  // extra args for the callback
} purge_t;

typedef struct table_t {
    struct radix_node_head *head4;    // IPv4 radix tree
    struct radix_node_head *head6;    // IPv6 radix tree
    size_t count4;
    size_t count6;
    purge_f_t *purge;                    // callback to free userdata
} table_t;

#define IPT_KEYOFFSET 8       // 8 bit offset to 1st byte of key
#define IPT_KEYLEN(k) (*k)    // 1st byte is 5 or 17 (includes itself)
#define IPT_KEYPTR(k) (k+1)   // 2nd byte starts actual key

#define IP4_KEYLEN 4
#define IP4_MAXMASK 32
#define IP4_PFXSTRLEN (INET_ADDRSTRLEN + 3)   // + /32

#define IP6_KEYLEN 16
#define IP6_MAXMASK 128
#define IP6_PFXSTRLEN (INET6_ADDRSTRLEN + 4)  // + /128

#define STR_IS_IP4(s) (strchr(s, (int)'.') ? 1 : 0)  // use it on fixed ipv4!
#define STR_IS_IP6(s) (strchr(s, (int)':') ? 1 : 0)

#define KEY_IS_IP4(k) (*((uint8_t *)(k))==(1+IP4_KEYLEN))
#define KEY_IS_IP6(k) (*((uint8_t *)(k))==(1+IP6_KEYLEN))

// radix tree macros
#define RDX_ISLEAF(rn) (rn->rn_bit < 0)
#define RDX_ISROOT(rn) (rn->rn_flags & RNF_ROOT)
#define RDX_ISRIGHT_CHILD(rn) (rn->rn_parent->rn_right == rn)

// used to interpolate the value of CONST into string: "%"STRINGIFY(x)"s"
#define STRINGIFY(x) STRINGIFY_x(x)
#define STRINGIFY_x(x) #x

// taken from radix.c & modified a bit
#define min(a, b) ((a) < (b) ? (a) : (b) )
#define RDX_MAX_KEYLEN    32

// -- PROTOTYPES

// -- key funcs

uint8_t *key_bystr(char *, int *, int *);
uint8_t *key_bylen(int, int);
const char *key_tostr(void *, char *);
int key_tolen(void *);
int key_incr(void *);
int key_decr(void *);
int key_cmp(void *, void *);
int key_masked(void *, void *);

// -- rdx funcs

int rdx_flush(struct radix_node *, void *);
struct radix_node *rdx_first(struct radix_node_head *);
struct radix_node *rdx_next(struct radix_node *);

// -- tbl funcs

int tbl_set(table_t *, char *, void *, void *);
int tbl_del(table_t *, char *, void *);
int tbl_walk(table_t *, walktree_f_t *, void *);
table_t *tbl_create(purge_f_t *);
entry_t * tbl_get(table_t *, char *);
entry_t * tbl_lpm(table_t *, char *);
void tbl_destroy(table_t **, void *);

#endif
