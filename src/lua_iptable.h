/* ---
 * title: lua_iptable reference
 * author: git.pdh
 * tags: Lua C-api
 * ...
 */

#ifndef lua_iptable_h
#define lua_iptable_h

/* # `lua_iptable.h`
 *
 * ## Defines
 *
 * ### `LUA_IPTABLE_ID`
 * Identity for the `table_t`-userdata.
 *
 * ### `LUA_IPT_ITR_GC`
 * Identity for the `itr_gc_t`-userdata.
 */

#define LUA_IPTABLE_ID "iptable"
#define LUA_IPT_ITR_GC "itr_gc"

/* ### ipt ERROR numbers
 */

typedef enum {
    LIPTE_NONE,
    LIPTE_AF,
    LIPTE_ARG,
    LIPTE_BIN,
    LIPTE_BINOP,
    LIPTE_FAIL,
    LIPTE_ITER,
    LIPTE_LIDX,
    LIPTE_LVAL,
    LIPTE_MLEN,
    LIPTE_PFX,
    LIPTE_RDX,
    LIPTE_TOBIN,
    LIPTE_TOSTR,
    LIPTE_UNKNOWN,
    LIPTE_ZMAX,  /* *must*be last entry */
} lipt_errno_t;


// the list *ends* with NULL, LIPTE_ZMAX *must* be last in enum above.
static const char *const LIPT_ERROR[] = {
    [LIPTE_NONE]    = "none",
    [LIPTE_AF]      = "wrong or unknown address family",
    [LIPTE_ARG]     = "wrong type of argument",
    [LIPTE_BINOP]   = "binary operation failed",
    [LIPTE_BIN]     = "illegal binary key/mask",
    [LIPTE_FAIL]    = "unspecified error",
    [LIPTE_ITER]    = "internal iteration error",
    [LIPTE_LIDX]    = "invalid Lua stack index",
    [LIPTE_LVAL]    = "invalid Lua stack (up)value",
    [LIPTE_MLEN]    = "invalid mask length",
    [LIPTE_PFX]     = "invalid prefix string",
    [LIPTE_RDX]     = "unhandled radix node type",
    [LIPTE_TOBIN]   = "error converting string to binary",
    [LIPTE_TOSTR]   = "error converting binary to string",
    [LIPTE_UNKNOWN] = "unknown error number",
    [LIPTE_ZMAX]    = NULL,
};


#endif // ifndef lua_iptable_h
