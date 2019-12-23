/* ---
 * title: lua_iptable reference
 * author: hertogp
 * tags: Lua C-api
 * ...
 *
 * *Language bindings for iptable.c, which wraps radix.c*
 */

#ifndef lua_iptable_h
#define lua_iptable_h

/* # `lua_iptable.h`
 *
 * ## \#defines
 *
 * ### `LUA_IPTABLE_ID`
 * Identity for the `table_t`-userdata.
 *
 * ### `LUA_IPT_ITR_GC`
 * Identity for the `itr_gc_t`-userdata.
 */

#define LUA_IPTABLE_ID "iptable"
#define LUA_IPT_ITR_GC "itr_gc"

/* ### LIPTE errno's
 * 0. LIPTE_NONE     none
 * 0. LIPTE_AF       wrong or unknown address family
 * 0. LIPTE_ARG      wrong type of argument
 * 0. LIPTE_BIN      illegal binary key/mask
 * 0. LIPTE_BINOP    binary operation failed
 * 0. LIPTE_BUF      could not allocate memory
 * 0. LIPTE_FAIL     unspecified error
 * 0. LIPTE_ITER     internal iteration error
 * 0. LIPTE_LIDX     invalid Lua stack index
 * 0. LIPTE_LVAL     invalid Lua stack (up)value
 * 0. LIPTE_MLEN     invalid mask length
 * 0. LIPTE_PFX      invalid prefix string
 * 0. LIPTE_RDX      unhandled radix node type
 * 0. LIPTE_SPLIT    prefix already at max length
 * 0. LIPTE_TOBIN    error converting string to binary
 * 0. LIPTE_TOSTR    error converting binary to string
 * 0. LIPTE_UNKNOWN  unknown error number
 * 0. LIPTE_ZMAX     NULL (end of error string list)
 */

typedef enum {
    LIPTE_NONE,
    LIPTE_AF,
    LIPTE_ARG,
    LIPTE_BIN,
    LIPTE_BINOP,
    LIPTE_BUF,
    LIPTE_FAIL,
    LIPTE_ITER,
    LIPTE_LIDX,
    LIPTE_LVAL,
    LIPTE_MLEN,
    LIPTE_PFX,
    LIPTE_RDX,
    LIPTE_SPLIT,
    LIPTE_TOBIN,
    LIPTE_TOSTR,
    LIPTE_UNKNOWN,
    LIPTE_ZMAX,     /* MUST be last entry */
} lipt_errno_t;


// the list *ends* with NULL, LIPTE_ZMAX *must* be last in enum above.
static const char *const LIPT_ERROR[] = {
    [LIPTE_NONE]    = "none",
    [LIPTE_AF]      = "unknown address family",
    [LIPTE_ARG]     = "wrong type of argument",
    [LIPTE_BINOP]   = "binary operation failed",
    [LIPTE_BIN]     = "illegal binary key/mask",
    [LIPTE_BUF]     = "could not allocate memory",
    [LIPTE_FAIL]    = "unspecified error",
    [LIPTE_ITER]    = "internal iteration error",
    [LIPTE_LIDX]    = "invalid Lua stack index",
    [LIPTE_LVAL]    = "invalid Lua stack (up)value",
    [LIPTE_MLEN]    = "invalid mask length",
    [LIPTE_PFX]     = "invalid prefix string",
    [LIPTE_RDX]     = "unhandled radix node type",
    [LIPTE_SPLIT]   = "prefix already at max length",
    [LIPTE_TOBIN]   = "error converting string to binary",
    [LIPTE_TOSTR]   = "error converting binary to string",
    [LIPTE_UNKNOWN] = "unknown error number",
    [LIPTE_ZMAX]    = NULL,
};


#endif // ifndef lua_iptable_h
