// file lua_iptable.c -- Lua bindings for iptable

#include <malloc.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "radix.h"
#include "iptable.h"

#ifdef DEBUG
#include <stdio.h>
static void stackDump(lua_State *, const char *);
static void
stackDump (lua_State *L, const char *title)
{
    // print out the scalar value or type of args on the stack 
    int i;
    int top = lua_gettop(L); // depth of the stack
    printf("%20s : [", title);
    for (i = 1; i <= top; i++) { // repeat for each level
        switch (lua_type(L, i))
        {
            case LUA_TNIL: { printf("nil"); break; }
            case LUA_TBOOLEAN: { printf(lua_toboolean(L, i) ? "true" : "false"); break; }
            case LUA_TLIGHTUSERDATA: { printf("lud@%p", lua_touserdata(L, i)); break; }
            case LUA_TNUMBER: { printf("%g", lua_tonumber(L, i)); break; }
            case LUA_TSTRING: { printf("'%s'", lua_tostring(L, i)); break; }
            case LUA_TTABLE: { printf("{}"); break; }
            case LUA_TFUNCTION: { printf("f@%p", lua_touserdata(L, i)); break; }
            case LUA_TUSERDATA: { printf("ud%p", lua_touserdata(L, i)); break; }
            case LUA_TTHREAD: { printf("T%p", lua_touserdata(L, i)); break; }
            default: { printf("%s", lua_typename(L, i)); break; }
        }
        if (i<top) printf(" "); // put a separator
    }
    printf("]\n"); // end the listing

} // --  end stackDump
#define _DEBUG_ 1
#define DBG(stmt) do {if(_DEBUG_) { stmt; } } while (0)
#else
#define _DEBUG_ 0
#define DBG(stmt) {}
#endif // DEBUG


// lua_iptable defines

#define LUA_USERDATUM_ID "iptable"

// userdata functions

int *mk_data(int);               // its return value is stored as entry->value
void ud_purge(void *, void **);  // called with &entry->value for cleanup

int *mk_data(int ref)
{
  // for storing LUA_REGISTRYINDEX ref's in the radix tree
  int *p = calloc(1, sizeof(int));
  *p = ref;
  return p;
}

void
ud_purge(void *L, void **dta)
{
  // unref the userdata and free associated ref memory
  if (*dta) {
    luaL_unref((lua_State *)L, LUA_REGISTRYINDEX, *(int *)*dta);
    free(*dta);
  }
  *dta = NULL;
}


// - lua functions

int luaopen_iptable(lua_State *);

// - AUXILIARY funtions

table_t *checkUserDatum(lua_State *, int);
static int iter_kv(lua_State *);

// - USERDATA module functions

static int new(lua_State *);

// - USERDATA instance methods

static int get(lua_State *);
static int _gc(lua_State *);
static int _index(lua_State *);
static int _newindex(lua_State *);
static int _len(lua_State *);
static int _tostring(lua_State *);
static int _pairs(lua_State *);
static int sizes(lua_State *);


// USERDATA function array
static const struct luaL_Reg funcs [] = {
    {"new", new},
    {NULL, NULL}
};

// USERDATA methods array

static const struct luaL_Reg meths [] = {
    {"__gc", _gc},
    {"__index", _index},
    {"__newindex", _newindex},
    {"__len", _len},
    {"__tostring", _tostring},
    {"__pairs", _pairs},
    {"get", get},
    {"sizes", sizes},
    {NULL, NULL}
};

// libopen

int luaopen_iptable (lua_State *L)
{
                                            // []
    luaL_newmetatable(L, LUA_USERDATUM_ID);  // [ {} ]
    lua_pushvalue(L, -1);                   // [ {}, {} ]
    lua_setfield(L, -2, "__index");         // [ {} ]
    luaL_setfuncs(L, meths, 0);             // [ {+meths} ]
    luaL_newlib(L, funcs);                  // [ {+meths} {+funcs} ]

    return 1;
}

// helpers

table_t *
checkUserDatum (lua_State *L, int index)
{
    void **ud = luaL_checkudata(L, index, LUA_USERDATUM_ID);
    luaL_argcheck(L, ud != NULL, index, "`iptable' expected");
    return (table_t *)*ud;
}

static int
new (lua_State *L)
{
    // ud is a void** so tbl_destroy(&ud) gets to clear the table and set the
    // pointer to the table to NULL.
    void **ud = lua_newuserdata(L, sizeof(void **));
    *ud = tbl_create(ud_purge);             // ud_purge func to free values

    if (*ud == NULL) {
        lua_pushliteral(L, "error creating iptable");
        lua_error(L);
    }

    luaL_getmetatable(L, LUA_USERDATUM_ID); // [ud M]
    lua_setmetatable(L, 1);

    return 1;
}

static int
_gc(lua_State *L) {
    // __gc: utterly destroy the table
    table_t *ud = checkUserDatum(L, 1);
    tbl_destroy(&ud, L);
    return 0;  // Lua owns the memory for the pointer to-> *ud
}

// methods

static int
_newindex(lua_State *L)
{
    // __newindex() -- [ud pfx val]

    table_t *ud = checkUserDatum(L, 1);
    const char *s = luaL_checkstring(L, 2);
    int ref = LUA_NOREF;
    char *pfx = strdup(s); // get modifiable copy

    if (lua_isnil(L, -1))
       tbl_del(ud, pfx, L);
     else {
       ref = luaL_ref(L, LUA_REGISTRYINDEX);
       tbl_set(ud, pfx, mk_data(ref), L);
     }
    free(pfx);

    return 0;
}

static int
get(lua_State *L)
{
  // ipt:get() -- [ud pfx]
  // FIXME: not needed anymore since ipt[addr/mask] does specific match due to
  // the presence of the mask?

  // stackDump(L, "obj->get():");
  table_t *ud = checkUserDatum(L, 1);
  const char *s = luaL_checkstring(L, 2);
  char *pfx = strdup(s);
  entry_t *e = tbl_get(ud, pfx);
  free(pfx);

  if(e)
    lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
  else
    return 0;

  return 1;
}

static int
_index(lua_State *L)
{
    // __index() -- [ud pfx] or [ud name]
    // - no mask -> do longest prefix search,
    // - with mask -> do exact lookup of prefix with mask

    DBG(printf("__index():\n"));
    DBG(stackDump(L, "__index() ."));
    table_t *ud = checkUserDatum(L, 1);
    entry_t *e = NULL;
    char *pfx;
    const char *s = luaL_checkstring(L, 2);

    pfx = strdup(s);              // get modifiable copy
    e = strchr(s, '/') ? tbl_get(ud, pfx) : tbl_lpm(ud, pfx);
    free(pfx);

    if(e) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value);
        DBG(stackDump(L, "val by ref +"));
    } else {
        // else, not found or not a pfx -> might be func name
        lua_getmetatable(L, 1);   // [ud name M]
        DBG(stackDump(L, "metatable +"));
        lua_rotate(L, 2, 1);      // [ud M name]
        DBG(stackDump(L, "swap top ."));
        lua_gettable(L, -2);      // [ud M func] or [ud M nil]
        DBG(stackDump(L, "mt value -+"));

    }

    return 1;
}

static int
_len(lua_State *L)
{
    // ipt:size() -- [ud]  -- return both count4 and count6 (in that order)
  table_t *ud = checkUserDatum(L, 1);
  lua_pushinteger(L, ud->count4 + ud->count6);

  return 1;
}

static int
_tostring(lua_State *L)
{
    // ipt:size() -- [ud]  -- return both count4 and count6 (in that order)
  table_t *ud = checkUserDatum(L, 1);
  lua_pushfstring(L, "iptable{#ipv4=%d, #ipv6=%d}", ud->count4, ud->count6);

  return 1;
}

static int
sizes(lua_State *L)
{
    // ipt:size() -- [ud]  -- return both count4 and count6 (in that order)
  DBG(printf("size()():\n"));
  DBG(stackDump(L, "stack ."));
  table_t *ud = checkUserDatum(L, 1);
  lua_pushinteger(L, ud->count4);         // [ud count4]
  DBG(stackDump(L, "count4 ."));
  lua_pushinteger(L, ud->count6);         // [ud count4 count6]
  DBG(stackDump(L, "count6 ."));

  return 2;                               // [.., count4, count6]
}

static int
iter_kv(lua_State *L)
{
  // iter_kv() <-- [ud k] (key k is nil if first call)
  // - returns next [k v]-pair or nil to stop iteration
  DBG(printf("iter_kv():\n"));
  DBG(stackDump(L, "stack ."));

  table_t *ud = checkUserDatum(L, 1);
  struct radix_node *rn = lua_touserdata(L, lua_upvalueindex(1));
  entry_t *e = NULL;
  char saddr[IP6_PFXSTRLEN];

  if (rn == NULL || RDX_ISROOT(rn)) return 0; // we're done

  // push k,v onto stack
  key_tostr(rn->rn_key, saddr);
  e = (entry_t *)rn;
  lua_pushfstring(L, "%s/%d", saddr, key_tolen(rn->rn_mask)); // [ud k k']
  DBG(stackDump(L, "key +"));
  lua_rawgeti(L, LUA_REGISTRYINDEX, *(int *)e->value); // [ud k k' v']
  DBG(stackDump(L, "value +"));

  // get next node & save it for next time around
  rn = rdx_next(rn);
  if (rn == NULL && KEY_IS_IP4(e->rn[0].rn_key))
    rn = rdx_first(ud->head6);
  lua_pushlightuserdata(L, rn);                       // [ud k k' v' lud]
  DBG(stackDump(L, "next radix node +"));
  lua_replace(L, lua_upvalueindex(1));                // [ud k k' v']
  DBG(stackDump(L, "set upvalue(1) -"));

  return 2;                                           // [.., k', v']
}


static int
_pairs(lua_State *L)
{
  // __pairs(ipt('ipv4')) <-- [ud]
  // factory function for iterator (closure) function
  DBG(printf("__pairs():\n"));
  DBG( stackDump(L, "stack ."));

  table_t *ud = checkUserDatum(L, 1);
  struct radix_node *rn = rdx_first(ud->head4);
  if (rn == NULL)
    rn = rdx_first(ud->head6);

  if (rn == NULL) return 0;
  // save rn as 1st node
  lua_pushlightuserdata(L, rn);        // [ud lud]
  DBG(stackDump(L, "1st leaf +"));
  lua_pushcclosure(L, iter_kv, 1);     // [ud f]
  DBG(stackDump(L, "iter_f (1 arg) +-"));
  lua_rotate(L, 1, 1);                 // [f ud]
  DBG(stackDump(L, "swap ."));
  lua_pushnil(L);                      // [f ud nil]
  DBG(stackDump(L, "ctl_var +"));

  return 3;                        // [iter_f invariant ctl_var]
}
