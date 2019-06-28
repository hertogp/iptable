// file lua_iptable.c -- Lua bindings for iptable

#include <malloc.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <math.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"
#include "debug.h"

// lua_iptable defines

#define LUA_IPTABLE_ID "iptable"
#define AF_UNKNOWN(f) (f != AF_INET && f!= AF_INET6)

// lua functions

int luaopen_iptable(lua_State *);

// helper funtions

table_t *check_table(lua_State *, int);
static int check_binkey(lua_State *, int, uint8_t *, size_t *);
const char *check_pfxstr(lua_State *, int, size_t *);
static int *ud_create(int);                // userdata stored as entry->value
static void usr_delete(void *, void **);    // usr_delete(L, &ud)
static int iter_hosts(lua_State *);
static int iter_kv(lua_State *);
static int iter_more(lua_State *);
static int iter_radix(lua_State *);
static int cb_collect(struct radix_node *, void *);

// radix iter helpers

void iptL_push_fstr(lua_State *, const char *, const char *, const void *);
void iptL_push_int(lua_State *, const char *, int);
static int push_rdx_node_head(lua_State *, struct radix_node_head *);
static int push_rdx_node(lua_State *, struct radix_node *);
static int push_rdx_head(lua_State *, struct radix_head *);
static int push_rdx_mask_head(lua_State *, struct radix_mask_head *);
static int push_rdx_mask(lua_State *, struct radix_mask *);

// iptable module functions

static int ipt_new(lua_State *);
static int ipt_tobin(lua_State *);
static int ipt_tostr(lua_State *);
static int ipt_tolen(lua_State *);
static int ipt_size(lua_State *);
static int ipt_address(lua_State *);
static int ipt_network(lua_State *);
static int ipt_broadcast(lua_State *);
static int ipt_mask(lua_State *);
static int ipt_iter_hosts(lua_State *);

// iptable instance methods

static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int counts(lua_State *);
// static int more(lua_State *);
static int more2(lua_State *);
static int less(lua_State *);
static int radixes(lua_State *);

// iptable module function array

static const struct luaL_Reg funcs [] = {
    {"new", ipt_new},
    {"tobin", ipt_tobin},
    {"tostr", ipt_tostr},
    {"tolen", ipt_tolen},
    {"address", ipt_address},
    {"network", ipt_network},
    {"broadcast", ipt_broadcast},
    {"mask", ipt_mask},
    {"size", ipt_size},
    {"hosts", ipt_iter_hosts},
    {NULL, NULL}
};

// iptable instance methods array

static const struct luaL_Reg meths [] = {
    {"__gc", _gc},
    {"__index", _index},
    {"__newindex", _newindex},
    {"__len", _len},
    {"__tostring", _tostring},
    {"__pairs", _pairs},
    {"counts", counts},
    // {"more", more},
    {"more2", more2},
    {"less", less},
    {"radixes", radixes},
    {NULL, NULL}
};

// libopen

int
luaopen_iptable (lua_State *L)
{
    // require("iptable") <-- ['iptable', '<path>/iptable.so' ]
    dbg_stack("inc(.) <--");

    luaL_newmetatable(L, LUA_IPTABLE_ID);   // [.., {} ]
    lua_pushvalue(L, -1);                   // [.., {}, {} ]
    lua_setfield(L, -2, "__index");         // [.., {__index={}} ]
    luaL_setfuncs(L, meths, 0);             // [.., {__index={m's}} ]
    luaL_newlib(L, funcs);                  // [.., {__index={m's}, f's} ]

    // lib AF constants
    lua_pushinteger(L, AF_INET);
    lua_setfield(L, -2, "AF_INET");
    lua_pushinteger(L, AF_INET6);
    lua_setfield(L, -2, "AF_INET6");

    // lib RDX node type constants
    lua_pushinteger(L, TRDX_NODE_HEAD);
    lua_setfield(L, -2, "RDX_NODE_HEAD");
    lua_pushinteger(L, TRDX_MASK_HEAD);
    lua_setfield(L, -2, "RDX_MASK_HEAD");
    lua_pushinteger(L, TRDX_NODE);
    lua_setfield(L, -2, "RDX_NODE");
    lua_pushinteger(L, TRDX_MASK);
    lua_setfield(L, -2, "RDX_MASK");
    lua_pushinteger(L, TRDX_HEAD);
    lua_setfield(L, -2, "RDX_HEAD");


    dbg_stack("out(1) ==>");

    return 1;
}

// helpers

table_t *
check_table (lua_State *L, int index)
{
    void **ud = luaL_checkudata(L, index, LUA_IPTABLE_ID);
    luaL_argcheck(L, ud != NULL, index, "`iptable' expected");
    return (table_t *)*ud;
}

static int
check_binkey(lua_State *L, int idx, uint8_t *buf, size_t *len)
{
    /*
     * Copy a binary key at index idx into buf whose size is MAX_BINKEY.
     * Returns 1 on success, 0 on failure.
     *
     * Note: a binary key is a byte array, 1st byte is LEN of the array.
     * So no '\0' is added here.
     *
     */

    const char *key = NULL;

    if (!lua_isstring(L, idx)) return 0;

    key = lua_tolstring(L, idx, len);
    if (key == NULL) return 0;

    if (IPT_KEYLEN(key) > MAX_BINKEY) return 0;
    if (*len < 1 || *len > MAX_BINKEY) return 0;

    memcpy(buf, key, *len);

    return 1;
}

const char *
check_pfxstr(lua_State *L, int idx, size_t *len)
{
    /* return const char to a (prefix) string.  NULL on failure. */
    const char *pfx = NULL;
    if (! lua_isstring(L, idx)) return NULL;
    pfx = lua_tolstring(L, idx, len);  // donot use luaL_tolstring!

    return pfx;
}

static int *ud_create(int ref)
{
    // store LUA_REGISTRYINDEX ref's in the radix tree as ptr->int
    int *p = calloc(1, sizeof(int));
    *p = ref;
    return p;
}

static void
usr_delete(void *L, void **refp)
{
    // unref the userdata and free associated ptr->int
    if (*refp) {
        luaL_unref((lua_State *)L, LUA_REGISTRYINDEX, *(int *)*refp);
        free(*refp);
    }
    *refp = NULL;
}


static int
iter_hosts(lua_State *L)
{
    // iter_hosts() <-- [prev.value]  ([nil] on first call)
    // actual iterator for ipt_iter_hosts()
    // we ignore prev.value, incr upvalue(1) instead till it equals upvalue(2)
    dbg_stack("inc(.) <--");

    size_t nlen = 0, slen = 0;
    uint8_t next[MAX_BINKEY], stop[MAX_BINKEY];
    char buf[MAX_STRKEY];

    if (!check_binkey(L, lua_upvalueindex(1), next, &nlen)) return 0;
    if (!check_binkey(L, lua_upvalueindex(2), stop, &slen)) return 0;
    if (key_cmp(next, stop) == 0) return 0;

    key_tostr(next, buf);                               // return cur val
    lua_pushstring(L, buf);

    key_incr(next);                                     // setup next val
    lua_pushlstring(L, (const char *)next, (size_t)IPT_KEYLEN(next));
    lua_replace(L, lua_upvalueindex(1));

    dbg_stack("out(1) ==>");

    return 1;
}

static int
iter_kv(lua_State *L)
{
    // iter_kv() <-- [t k] (key k is nil if first call)
    // - returns next [k' v']-pair or nil [] to stop iteration

    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
    entry_t *e = NULL;
    char saddr[MAX_STRKEY];

    if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

    // push k',v' onto stack
    key_tostr(rn->rn_key, saddr);
    e = (entry_t *)rn;
    lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [t_ud k k']
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value); // [t_ud k k' v']

    // get next node & save it for next time around
    rn = rdx_nextleaf(rn);
    if (rn == NULL && KEY_IS_IP4(e->rn[0].rn_key))
        rn = rdx_firstleaf(t->head6);
    lua_pushlightuserdata(L, rn);                       // [t_ud k k' v' lud]
    lua_replace(L, lua_upvalueindex(1));                // [t_ud k k' v']

    dbg_stack("out(2) ==>");

    return 2;                                           // [.., k', v']
}

/* TODO:
 *
 * static int iter_less(lua_State *);
 *
 * Iterate across less specific prefixes relative to a given prefix.
 * (replace the current callback based version that returns all results at once
 * in an array, using tbl_walk in combination with cb_collect)
 *
 */

/* TODO:
 *
 * static int iter_masks(lua_State *);
 *
 * Iterate across masks used in the tree. Takes 1 or 2 AF_family args to
 * indicate which type(s) of masks should be iterated
 *
 */

static int
iter_more(lua_State *L)
{
    /*
     * Iterate across more specific prefixes one at a time.
     * - top points to subtree where possible matches are located
     * - rn is the current leaf under consideration
     */

    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    struct radix_node *top = lua_touserdata(L, lua_upvalueindex(1));
    struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(2));
    int maxb = lua_tointeger(L, lua_upvalueindex(3));
    size_t dummy;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];

    if(!check_binkey(L, lua_upvalueindex(4), addr, &dummy)){
      dbg_msg("check_binkey failed for addr, upval(%d)", 4);
      return 0;
    }
    if(!check_binkey(L, lua_upvalueindex(5), mask, &dummy)) {
      dbg_msg("check_binkey failed for mask, upval(%d)", 5);
      return 0;
    }

    dbg_msg("search %s/%d\n", key_tostr(addr, buf), key_tolen(mask));
    dbg_msg("    rn %p\n", (void*)rn);

    if (rn == NULL) return 0;  /* we're done */

    /* check LEAF and duplicates for more specific prefixes */
    int matched = 0, done = 0;
    while (! matched && ! done) {

        /* only non-ROOT leafs may match */
        if(!RDX_ISROOT(rn)
            && rn->rn_bit <= maxb
            && key_isin(addr, rn->rn_key, mask)) {

            if (! key_tostr(rn->rn_key, buf)) return 0;
            lua_pushfstring(L, "%s/%d", buf, key_tolen(rn->rn_mask));
            matched = 1;
        }

        dbg_msg("top %p, maxb %d, rn %p, rn_bit %d, match %d",
          (void *)top, maxb, (void *)rn, rn->rn_bit, matched);

        /* find next leaf node to try later on */
        if (rn->rn_dupedkey) {
            rn = rn->rn_dupedkey;      /* more dups to try */
        } else {

            /* when to stop? */
            if (RDX_ISLEAF(rn) && RDX_ISLEAF(rn->rn_parent)
                && RDX_ISROOT(rn->rn_parent)
                && (rn->rn_flags & RNF_NORMAL)
               ){
              done = 1;
            }

            /* end of the dupedkey chain, go back to top of chain */
            while(RDX_ISLEAF(rn->rn_parent) && !RDX_ISROOT(rn->rn_parent)) {
                rn=rn->rn_parent;
            }

            while(RDX_ISRIGHT_CHILD(rn) && !RDX_ISROOT(rn)
                && rn->rn_parent != top) {
                rn = rn->rn_parent;
            }

            /* If rn is top's right child, we're done */
            if (rn == top->rn_right) done = 1;
            /* goto first left leaf of parent's right subtree */
            for (rn = rn->rn_parent->rn_right; !RDX_ISLEAF(rn); )
                rn = rn->rn_left;
            if (RDX_ISROOT(rn->rn_parent)) done = 1;
        }

        if (done) {
            lua_pushlightuserdata(L, NULL);
            lua_replace(L, lua_upvalueindex(2));
        } else if (matched) {
            lua_pushlightuserdata(L, rn);
            lua_replace(L, lua_upvalueindex(2));
        }
    }

    if (matched) return 1;
    return 0;
}

static int
iter_radix(lua_State *L)
{
    // iter_radix() <-- [ud k] ([nil nil] at first call)
    // - return current node as a Lua table or nil to stop iteration
    // - save next (type, node) as/in upvalues 1 resp. 2
    dbg_stack("inc(.) <--");
    table_t *t = check_table(L, 1);
    void *node;
    int type;

    if (! rdx_nextnode(t, &type, &node)) return 0; // we're done

    dbg_msg(">> node %p, type %d", node, type);
    switch (type) {
        case TRDX_NODE_HEAD: return push_rdx_node_head(L, node);
        case TRDX_HEAD:      return push_rdx_head(L, node);
        case TRDX_NODE:      return push_rdx_node(L, node);
        case TRDX_MASK_HEAD: return push_rdx_mask_head(L, node);
        case TRDX_MASK:      return push_rdx_mask(L, node);
    }
    dbg_msg(" `-> unhandled node type %d!", type);
    return 0;
}

static int
cb_collect(struct radix_node *rn, void *LL)
{
    // collect prefixes into table on top <-- [t_ud, pfx bool* ref]
    // - where bool* may be absent.
    // - Order of args follows walktree_f_t definition
    lua_State *L = LL;
    dbg_stack("cb_more()");                         // after *L=LL (it needs L)

    char addr[MAX_STRKEY];
    int mlen = -1, tlen = 0;

    if (! lua_istable(L, -1)) return 1;
    if (! key_tostr(rn->rn_key, addr)) return 1;
    mlen = key_tolen(rn->rn_mask);

    lua_len(L, -1);                                 // get table length
    tlen = lua_tointeger(L, -1) + 1;                // new array index
    lua_pop(L,1);

    lua_pushfstring(L, "%s/%d", addr, mlen);        // more specific pfx
    lua_seti(L, -2, tlen);                          // insert in array

    dbg_stack("out(0) ==>");

    return 1;                                       // ignored return value
}

// iter_radix helpers

void iptL_push_fstr(lua_State *L, const char *k, const char *fmt, const void *v)
{
    if (! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table? ->");
        return;
    }
    lua_pushstring(L, k);
    lua_pushfstring(L, fmt, v);
    lua_settable(L, -3);
}

void iptL_push_int(lua_State *L, const char *k, int v)
{
    if (! lua_istable(L, -1)) {
        dbg_msg("need stack top to be a %s", "table");
        dbg_stack("not a table ? ->");
        return;
    }
    lua_pushstring(L, k);
    lua_pushinteger(L, v);
    lua_settable(L, -3);
}


static int
push_rdx_node_head(lua_State *L, struct radix_node_head *rnh)
{
    // create table and populate its fields for rnh
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rnh);
    iptL_push_int(L, "_TYPE_", TRDX_NODE_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_NODE_HEAD");

    // rh goes into a subtable
    lua_pushliteral(L, "rh");
    push_rdx_head(L, &rnh->rh);
    lua_settable(L, -3);

    // rnh_nodes -> {_MEM_,..{{RDX[0]}, {RDX[1]}, {RDX[2]}}}
    lua_pushliteral(L, "rnh_nodes");

    // new subtable: array of 3 RDX nodes; table has MEM/NAME but no type
    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rnh->rnh_nodes);
    iptL_push_fstr(L, "_NAME_", "%s", "RNH_NODES[3]");
    lua_pushinteger(L, 1);
    push_rdx_node(L, &rnh->rnh_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    push_rdx_node(L, &rnh->rnh_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    push_rdx_node(L, &rnh->rnh_nodes[2]);
    lua_settable(L, -3);  // last entry is subtable

    lua_settable(L, -3);


    dbg_stack("out(1) ==>");
    return 1;
}

static int
push_rdx_node(lua_State *L, struct radix_node *rn)
{
    // create table and populate its fields for rn
    // - uses the convenience rn->field_names
    char key[MAX_STRKEY];
    dbg_stack("inc(.) <--");

    lua_newtable(L);

    iptL_push_fstr(L, "_MEM_", "%p", rn);
    iptL_push_int(L, "_TYPE_", TRDX_NODE);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_NODE");

    iptL_push_fstr(L, "rn_mklist", "%p", rn->rn_mklist);
    iptL_push_fstr(L, "rn_parent", "%p", rn->rn_parent);
    iptL_push_int(L, "rn_bit", rn->rn_bit);
    // its a char, pushed as int => print("%02x", 0xff & int_val)
    iptL_push_int(L, "rn_bmask", rn->rn_bmask);
    iptL_push_int(L, "rn_flags", rn->rn_flags);

    // set _RNF_FLAGs_
    if (rn->rn_flags & RNF_NORMAL)
        iptL_push_int(L, "_NORMAL_", 1);
    if (rn->rn_flags & RNF_ROOT)
        iptL_push_int(L, "_ROOT_", 1);
    if (rn->rn_flags & RNF_ACTIVE)
        iptL_push_int(L, "_ACTIVE_", 1);

    if(RDX_ISLEAF(rn)) {
      iptL_push_int(L, "_LEAF_", 1);
      iptL_push_fstr(L, "rn_key", "%s", key_tostr(rn->rn_key, key));
      iptL_push_fstr(L, "rn_mask", "%s", key_tostr(rn->rn_mask, key));
      iptL_push_fstr(L, "rn_dupedkey", "%p", rn->rn_dupedkey);

      /* additional diagnostics */
      if (rn->rn_key)
        iptL_push_int(L, "_rn_key_LEN", 0xff & IPT_KEYLEN(rn->rn_key));
      else
        iptL_push_int(L, "_rn_key_LEN", -1);

      if (rn->rn_mask)
        iptL_push_int(L, "_rn_mask_LEN", IPT_KEYLEN(rn->rn_mask));
      else
        iptL_push_int(L, "_rn_mask_LEN", -1); /* may happen in mask tree */


    } else {
      iptL_push_int(L, "_INTERNAL_", 1);
      iptL_push_int(L, "rn_offset", rn->rn_offset);
      iptL_push_fstr(L, "rn_left", "%p", rn->rn_left);
      iptL_push_fstr(L, "rn_right", "%p", rn->rn_right);
    }

    dbg_stack("out ==>");

    return 1;
}

static int
push_rdx_head(lua_State *L, struct radix_head *rh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rh);
    iptL_push_int(L, "_TYPE_", TRDX_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_HEAD");

    iptL_push_fstr(L, "rnh_treetop", "%p", rh->rnh_treetop);
    iptL_push_fstr(L, "rnh_masks", "%p", rh->rnh_masks);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
push_rdx_mask_head(lua_State *L, struct radix_mask_head *rmh)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rmh);
    iptL_push_int(L, "_TYPE_", TRDX_MASK_HEAD);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_MASK_HEAD");

    lua_pushliteral(L, "head");
    push_rdx_head(L, &rmh->head);
    lua_settable(L, -3);

    lua_pushliteral(L, "mask_nodes");

    // new subtable: an array of 3 radix_node's
    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rmh->mask_nodes);
    iptL_push_fstr(L, "_NAME_", "%s", "MASK_NODES[3]");
    lua_pushinteger(L, 1);
    push_rdx_node(L, &rmh->mask_nodes[0]);
    lua_settable(L, -3);
    lua_pushinteger(L, 2);
    push_rdx_node(L, &rmh->mask_nodes[1]);
    lua_settable(L, -3);
    lua_pushinteger(L, 3);
    push_rdx_node(L, &rmh->mask_nodes[2]);
    lua_settable(L, -3);

    lua_settable(L, -3);  // mask_nodes -> subtable/array

    dbg_stack("out(1) ==>");

    return 1;
}

static int
push_rdx_mask(lua_State *L, struct radix_mask *rm)
{
    // create table and populate its fields for rn
    dbg_stack("inc(.) <--");

    char key[MAX_STRKEY];

    lua_newtable(L);
    iptL_push_fstr(L, "_MEM_", "%p", rm);
    iptL_push_int(L, "_TYPE_", TRDX_MASK);
    iptL_push_fstr(L, "_NAME_", "%s", "RADIX_MASK");

    iptL_push_int(L, "rm_bit", rm->rm_bit);
    iptL_push_int(L, "rm_unused", rm->rm_unused);
    iptL_push_int(L, "rm_flags", rm->rm_flags);

    // set _RNF_FLAGs_
    if (rm->rm_flags & RNF_NORMAL) iptL_push_int(L, "_NORMAL_", 1);
    if (rm->rm_flags & RNF_ROOT)   iptL_push_int(L, "_ROOT_", 1);
    if (rm->rm_flags & RNF_ACTIVE) iptL_push_int(L, "_ACTIVE_", 1);

    iptL_push_fstr(L, "rm_mklist", "%p", rm->rm_mklist);
    iptL_push_int(L, "rm_refs", rm->rm_refs);

    if (rm->rm_flags & RNF_NORMAL) {
      // NOTE: if its a NORMAL 'radix_mask' then union -> rm_leaf else rm_mask
      // - see radix.c:377 and and radix.c:773
      iptL_push_int(L, "_LEAF_", 1);
      iptL_push_fstr(L, "rm_leaf", "%p", rm->rm_leaf);

    } else {
      iptL_push_int(L, "_INTERNAL_", 1);
      iptL_push_fstr(L, "rm_mask", "%s", key_tostr(rm->rm_mask, key));
    }

    dbg_stack("out(1) ==>");

    return 1;
}


// iptable module functions

static int
ipt_new(lua_State *L)
{
    // ipt.new()  <-- []
    // - void** t -> so tbl_destroy(&t) sets t=NULL when done clearing it
    // - Return a new iptable instance.  Bail on memory errors.
    dbg_stack("inc(.) <--");

    void **t = lua_newuserdata(L, sizeof(void **));
    *t = tbl_create(usr_delete);             // usr_delete func to free values

    if (*t == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_IPTABLE_ID); // [ud M]
    lua_setmetatable(L, 1);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_tobin(lua_State *L)
{
    // iptable.tobin(strKey) <-- [str]
    // Return binary form, masklength & AF for a given prefix, nil on errors
    dbg_stack("inc(.) <--");

    int af, mlen;
    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    const char *pfx = check_pfxstr(L, 1, &len);

    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;

    lua_pushlstring(L, (const char*)addr, IPT_KEYLEN(addr));
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_tostr(lua_State *L)
{
    // iptable.tostr(binKey) <-- [binkey]
    // Return string representation for a binary key, nil on errors
    dbg_stack("inc(.) <--");

    uint8_t key[MAX_BINKEY];
    char str[MAX_STRKEY];
    size_t len = 0;

    if (!check_binkey(L, 1, key, &len)) return 0;
    if (len != (size_t)IPT_KEYLEN(key)) return 0; // illegal binary
    if (key_tostr(key, str) == NULL) return 0;

    lua_pushstring(L, str);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_tolen(lua_State *L)
{
    // iptable.tolen(binKey) <-- [key]
    // Return the number of consequtive msb 1-bits, nil on errors.
    // - stops at the first zero bit.
    dbg_stack("inc(.) <--");

    uint8_t buf[MAX_BINKEY];
    size_t len = 0;
    int mlen = -1;

    if (!check_binkey(L, 1, buf, &len)) return 0;

    mlen = key_tolen(buf);
    lua_pushinteger(L, mlen);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_size(lua_State *L)
{
    // iptable.size(strKey) <-- [str]
    // Return the number of hosts in a given prefix, nil on errors
    // - uses Lua's arithmatic (2^hostbits), since ipv6 can get large.

    dbg_stack("inc(.) <--");

    uint8_t addr[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, hlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (AF_UNKNOWN(af)) return 0;

    hlen = af == AF_INET ? IP4_MAXMASK : IP6_MAXMASK;
    hlen = mlen < 0 ? 0 : hlen - mlen;              // mlen<0 means host addr
    lua_pushinteger(L, 2);
    lua_pushinteger(L, hlen);
    lua_arith(L, LUA_OPPOW);
    dbg_stack("out(1) ==>");

    return 1;
}

static int
ipt_address(lua_State *L)
{
    // iptable.address(strKey) <-- [str]
    // Return host address, masklen & af for a given prefix, nil on errors
    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_tostr(addr, buf)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_network(lua_State *L)
{
    // iptable.network(strKey) <-- [str]
    // Return network address & masklen for a given prefix, nil on errors
    dbg_stack("inc(.) <--");

    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1;
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_network(addr, mask)) return 0;
    if (! key_tostr(addr, buf)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_broadcast(lua_State *L)
{
    // iptable.broadcast(strKey) <-- [str]
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1;
    size_t len = 0;
    char buf[MAX_STRKEY];
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    const char *pfx = NULL;

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0;
    if (! key_bylen(af, mlen, mask)) return 0;
    if (! key_broadcast(addr, mask)) return 0;
    if (! key_tostr(addr, buf)) return 0;

    lua_pushstring(L, buf);
    lua_pushinteger(L, mlen);
    lua_pushinteger(L, af);

    dbg_stack("out(3) ==>");

    return 3;
}

static int
ipt_mask(lua_State *L)
{
    // iptable.mask(af, mlen) <-- [num]
    // Returns mask (as string) for mlen bits given. Nil on errors
    // - mlen < 0 means inverse mask of mlen, so mlen = -8 -> 0.255.255.255
    dbg_stack("inc(.) <--");

    int af = AF_UNSPEC, mlen = -1, isnum = 0;
    char buf[MAX_STRKEY];
    uint8_t mask[MAX_BINKEY];

    af = lua_tointegerx(L, 1, &isnum);
    if (! isnum) return 0;
    if (AF_UNKNOWN(af)) return 0;

    mlen = lua_tointegerx(L, 2, &isnum);
    if (! isnum) return 0;
    if (! key_bylen(af, mlen < 0 ? -mlen : mlen, mask)) return 0;
    if (mlen < 0 && ! key_invert(mask)) return 0;
    if (! key_tostr(mask, buf)) return 0;

    lua_pushstring(L, buf);

    dbg_stack("out(1) ==>");

    return 1;
}


static int
ipt_iter_hosts(lua_State *L)
{
    // iptable.iter_hosts(pfx) <-- [str, incl] (inclusive is optional)
    // Setup iteration across hosts in a given prefix.
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    int fail = 0;  // even on failure, gotta push iterfunc with 2 upvalues
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY], stop[MAX_BINKEY];
    const char *pfx = NULL;

    if (lua_gettop(L) == 2 && lua_isboolean(L, 2))
        inclusive = lua_toboolean(L, 2);  // include netw/bcast (or not)

    pfx = check_pfxstr(L, 1, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) fail = 1;
    if (! key_bystr(pfx, &mlen, &af, stop)) fail = 1;
    if (! key_bylen(af, mlen, mask)) fail = 1;
    if (! key_network(addr, mask)) fail = 1;           // start = network
    if (! key_broadcast(stop, mask)) fail = 1;         // stop = bcast

    if (inclusive)                                     // incl network/bcast?
        key_incr(stop);
    else if (key_cmp(addr, stop) < 0)
        key_incr(addr);  // not inclusive, so donot 'iterate' a host ip addr.

    if (fail) {
        lua_pushnil(L);
        lua_pushnil(L);
        dbg_stack("fail! 2+");
    } else {
        lua_pushlstring(L, (const char *)addr, IPT_KEYLEN(addr));
        lua_pushlstring(L, (const char *)stop, IPT_KEYLEN(stop));
        dbg_stack("suc6! 2+");
    }
    lua_pushcclosure(L, iter_hosts, 2);  // [.., func]

    dbg_stack("out(1) ==>");

    return 1;
}

// iptable instance methods

static int
_gc(lua_State *L) {
    // __gc: utterly destroy the table
    dbg_stack("inc(.) <--");

    table_t *ud = check_table(L, 1);
    tbl_destroy(&ud, L);

    dbg_stack("out(0) ==>");

    return 0;  // Lua owns the memory for the pointer to-> *ud
}

static int
_newindex(lua_State *L)
{
    // __newindex() -- [tbl_ud pfx val]
    dbg_stack("inc(.) <--");

    void *ud;               // userdata to store (will be ptr->int)
    const char *pfx = NULL;
    size_t len = 0;
    int ref = LUA_NOREF;
    table_t *t = check_table(L, 1);

    pfx = check_pfxstr(L, 2, &len);
    dbg_msg("got pfx %s", pfx);

    if (lua_isnil(L, -1)) {
        dbg_msg("tbl_del on %s", pfx);
        tbl_del(t, pfx, L);
    }
    else {
        ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop top & store in registry
        ud = ud_create(ref);
        if (!tbl_set(t, pfx, ud, L)) {
            usr_delete(L, &ud);
            dbg_msg("unref'd %d", ref);
        } else {
            dbg_msg("stored as ref %d", ref);
        }
    }

    dbg_stack("out(0) ==>");

    return 0;
}

static int
_index(lua_State *L)
{
    // __index() -- [ud pfx] or [ud name]
    // - no mask -> do longest prefix search,
    // - with mask -> do exact lookup of prefix with mask
    // - if pfx lookup fails -> try metatable
    dbg_stack("inc(.) <--");

    entry_t *entry = NULL;
    size_t len = 0;
    const char *pfx = NULL;

    table_t *t = check_table(L, 1);
    pfx = check_pfxstr(L, 2, &len);

    if(pfx)
        entry = strchr(pfx, '/') ? tbl_get(t, pfx) : tbl_lpm(t, pfx);

    if(entry)
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)entry->value); // [tbl k v]
    else {
        if (luaL_getmetafield(L, 1, pfx) == LUA_TNIL)
            return 0;
    }

    dbg_stack("out(1) ==>");

    return 1;
}

static int
_len(lua_State *L)
{
    // #ipt <-- [ud]  --> return sum of count4 and count6
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4 + t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
_tostring(lua_State *L)
{
    // as string: iptable{#ipv4=.., #ipv6=..}
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", t->count4, t->count6);

    dbg_stack("out(1) ==>");

    return 1;
}

static int
counts(lua_State *L)
{
    // ipt:size() <-- [t_ud]  -- return both count4 and count6 (in that order)
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    lua_pushinteger(L, t->count4);         // [t_ud count4]
    lua_pushinteger(L, t->count6);         // [t_ud count4 count6]

    dbg_stack("out(2) ==>");

    return 2;                              // [.., count4, count6]
}

static int
_pairs(lua_State *L)
{
    // __pairs(ipt) <-- [t_ud]
    dbg_stack("inc(.) <--");

    table_t *t = check_table(L, 1);
    struct radix_node *rn = rdx_firstleaf(t->head4);
    if (rn == NULL)
        rn = rdx_firstleaf(t->head6);

    // if (rn == NULL) return 0;

    lua_pushlightuserdata(L, rn);        // [t_ud lud], rn is 1st node
    lua_pushcclosure(L, iter_kv, 1);     // [t_ud f], rn as upvalue(1)
    lua_rotate(L, 1, 1);                 // [f t_ud]
    lua_pushnil(L);                      // [f t_ud nil]

    dbg_stack("out(3) ==>");

    return 3;                            // [iter_f invariant ctl_var]
}

/* static int */
/* more(lua_State *L) */
/* { */
/*     // ipt:more(pfx, inclusive) <-- [t_ud pfx bool] */
/*     // Return array of more specific prefixes in the iptable */
/*     dbg_stack("inc(.) <--"); */

/*     size_t len = 0; */
/*     int af = AF_UNSPEC, mlen = -1, inclusive = 0; */
/*     uint8_t addr[MAX_BINKEY]; */
/*     const char *pfx = NULL; */

/*     table_t *t = check_table(L, 1); */
/*     pfx = check_pfxstr(L, 2, &len); */
/*     if (! key_bystr(pfx, &mlen, &af, addr)) return 0; // invalid prefix */
/*     if (af == AF_UNSPEC) return 0;                    // unknown family */

/*     if (lua_gettop(L) == 3 && lua_isboolean(L, 3)) */
/*         inclusive = lua_toboolean(L, 3);  // include search prefix (or not) */

/*     lua_newtable(L);                     // collector table on top */
/*     if (! tbl_more(t, pfx, inclusive, cb_collect, L)) return 0; */

/*     dbg_stack("out(1) ==>"); */

/*     return 1; */
/* } */

static inline int subtree_fail(struct radix_node *, int);
static inline int subtree_fail(struct radix_node *rn, int mlen) {
  return RDX_ISROOT(rn)
      && RDX_ISLEAF(rn)
      && mlen !=0
      && !(rn->rn_dupedkey);
}

static int
more2(lua_State *L)
{
    // ipt:more(pfx, inclusive) <-- [t_ud pfx bool], bool is optional
    // iterate across more specific prefixes

    dbg_stack("inc(.) <--");


    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, maxb = -1;
    uint8_t addr[MAX_BINKEY], mask[MAX_BINKEY];
    struct radix_node_head *head = NULL;
    struct radix_node *rn = NULL, *top = NULL;

    table_t *t = check_table(L, 1);
    const char *pfx = check_pfxstr(L, 2, &len);

    if (! key_bystr(pfx, &mlen, &af, addr)) {
      lua_pushfstring(L, "more(): invalid prefix %s", lua_tostring(L, 2));
      lua_error(L);
    }
    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        maxb = 0;

    lua_pop(L, lua_gettop(L) - 1);  // [t_ud]

    if (af == AF_INET) {
      head = t->head4;
      mlen = mlen < 0 ? IP4_MAXMASK : mlen;
    } else if (af == AF_INET6) {
      head = t->head6;
      mlen = mlen < 0 ? IP6_MAXMASK : mlen;
    } else return 0;

    /* if (! key_bylen(af, mlen, mask)) return 0; */
    /* if (! key_network(addr, mask)) return 0; */
    if (! key_bylen(af, mlen, mask) || ! key_network(addr, mask)) {
      lua_pushliteral(L, "more(): error converting prefix");
      lua_error(L);
    }

    /*
     * rn_bit >= maxb, and in case mlen==0 and 0/0 is present in the tree,
     * it's rn_bit is -1 and not -1-IPT_KEYOFFSET-mlen like for all other
     * leafs
     *
     */
    maxb = (mlen == 0) ? maxb - 1 : maxb - 1 - IPT_KEYOFFSET - mlen;
    dbg_msg("rn_bit <= maxb %d", maxb);

    /* descend the tree towards a possible matching leaf */
    for(rn = head->rh.rnh_treetop; !RDX_ISLEAF(rn);) //rn->rn_bit >= 0;)
        if (addr[rn->rn_offset] & rn->rn_bmask)
            rn = rn->rn_right;
        else
            rn = rn->rn_left;

    dbg_msg("1st leaf %p, rn_bit %d", (void *)rn, rn->rn_bit);

    if (RDX_ISROOT(rn) && RDX_ISLEAF(rn)) {
      dbg_msg("1st leaf %p is ROOT node with dupedkey %p",
          (void *)rn, (void *)rn->rn_dupedkey);
    }

    /* go up to INTERNAL node governing the tree of this leaf */
    for(top=rn->rn_parent; top->rn_bit>mlen+IPT_KEYOFFSET; top=top->rn_parent)
      if (RDX_ISROOT(top)) break;

    /* goto LEFT subtree, first LEAF */
    for (rn = top; !RDX_ISLEAF(rn); rn=rn->rn_left)
      ;

    dbg_msg("tree top %p, rn_bit %d", (void *)top, top->rn_bit);
    dbg_msg("2nd leaf %p, rn_bit %d", (void *)rn, rn->rn_bit);

    /*
     * If the search ends up on the default ROOT 0/0 node, it has failed if
     * mlen != 0 and no matches are possible.  Note: ROOT's 0.0.0.0 rn_key has
     * a keylength of 0 bytes(!) and thus will always match any other key when
     * using key_isin to check for a match.  Hence the first check is for
     * ISROOT and mlen !=0;
     *
     * If the search ends up on some 'real' LEAF node, key_isin can be used to
     * check the leaf actually matches.  Required since the trie is path
     * compressed.
     *
     */

    /* int left_tree_fail = RDX_ISROOT(rn) */
    /*   && RDX_ISLEAF(rn) */
    /*   && mlen !=0 */
    /*   && !(rn->rn_dupedkey); */

    if (subtree_fail(rn, mlen) || !key_isin(addr, rn->rn_key, mask)) {
        /* switch to RIGHT subtree */
        for (rn = top->rn_right; !RDX_ISLEAF(rn); rn=rn->rn_left)
            ;
        if (subtree_fail(rn, mlen) || !key_isin(addr, rn->rn_key, mask))
          rn = NULL;
        dbg_msg("switched to right subtree, rn %p", (void*)rn);
    }

    dbg_msg("3rd leaf %p", (void *)rn);

    /* the upvalues for the iterator: subtreetop, current node & maxbit */
    lua_pushlightuserdata(L, top);
    lua_pushlightuserdata(L, rn);
    lua_pushinteger(L, maxb);
    lua_pushlstring(L, (const char *)addr, (size_t)IPT_KEYLEN(addr));
    lua_pushlstring(L, (const char *)mask, (size_t)IPT_KEYLEN(mask));

    /* setup [iter_func invariant initial_ctl_var] */
    lua_pushcclosure(L, iter_more, 5);                        // [t f]
    lua_rotate(L, 1, 1);                                      // [f t]
    lua_pushnil(L);                                           // [f t nil]

    dbg_stack("out(1) ==>");

    return 3;
}

static int
less(lua_State *L)
{
    // ipt:less(pfx, inclusive) <-- [ud pfx bool*]
    // Return array of less specific prefixes in the iptable
    dbg_stack("inc(.) <--");

    size_t len = 0;
    int af = AF_UNSPEC, mlen = -1, inclusive = 0;
    uint8_t addr[MAX_BINKEY];
    const char *pfx = NULL;

    table_t *t = check_table(L, 1);
    pfx = check_pfxstr(L, 2, &len);
    if (! key_bystr(pfx, &mlen, &af, addr)) return 0; // invalid prefix
    if (af == AF_UNSPEC) return 0;                    // unknown family

    if (lua_gettop(L) == 3 && lua_isboolean(L, 3))
        inclusive = lua_toboolean(L, 3);              // include search prefix (or not)

    lua_newtable(L);                                  // collector table
    if (! tbl_less(t, pfx, inclusive, cb_collect, L)) return 0;

    dbg_stack("out(1) ==>");

    return 1;
}

static int
radixes(lua_State *L)
{
    // ipt:radix(AF)  <-- [t_ud af1, af2, ...]
    // Iterate across all radix nodes in 1+ radix trees (iter_radix())
    // - iter_radix() yields the radix tree's C-structs as Lua tables
    dbg_stack("inc(.) <--");

    int isnum = 0, af = AF_UNSPEC, afs = IPT_UNSPEC;
    table_t *t = check_table(L, 1);

    if (lua_gettop(L) < 2) {
        lua_pushfstring(L, "ipt:radixes(): need AF_INET, AF_INET6 or both");
        lua_error(L);
    }
    while(lua_gettop(L) > 1) {
      af = lua_tointegerx(L, lua_gettop(L), &isnum);
      if (!isnum || AF_UNKNOWN(af)) {
        lua_pushfstring(L, "ipt:radixes(): unknown AF_family %d", af);
        lua_error(L);
      }
      switch (af) {
        case AF_INET:
          afs |= IPT_INET;
          break;
        case AF_INET6:
          afs |= IPT_INET6;
          break;
        default:
          return 0;
      }
      lua_pop(L, 1);
      dbg_stack("popped af -");
    }

    if (! rdx_firstnode(t, afs)) return 0;

    dbg_stack("upvalues(0)");
    lua_pushcclosure(L, iter_radix, 0);             // [t_ud iter_f]
    lua_rotate(L, 1, 1);                            // [iter_f t_ud]

    dbg_stack("out(2) ==>");

    return 2;                                       // [iter_f invariant]
}
