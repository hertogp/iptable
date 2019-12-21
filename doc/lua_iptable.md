---
title: lua_iptable reference
author: git.pdh
tags: Lua C-api
...

# `lua_iptable.h`

## Defines

### `LUA_IPTABLE_ID`
Identity for the `table_t`-userdata.

### `LUA_IPT_ITR_GC`
Identity for the `itr_gc_t`-userdata.

### ipt ERROR numbers

# `lua_iptable.c`
Lua bindings for iptable


## Structures

### `itr_gc_t`

The `itr_gc_t` type  has 1 member: `table_t *t` and serves only to create a
userdata to be supplied as an upvalue to each iterator function.  That
userdata has a metatable with a `__gc` garbage collector, (see `ipt_itr_gc`)
which will remove radix nodes in `t` that are (still) flagged for deletion
only when it is safe to do so (i.e. `t->itr_lock` has reached zero).


## lualib


### `luaopen_iptable`
```c
  int luaopen_iptable(lua_State *L);
```
Called by Lua upon `require("iptable")` to initialize the module.  Returns
`iptable`'s module-table with the module functions and constants.  Instance
methods go into its metatable.


## error handlers


### `lipt_error`
```c
static int lipt_error(lua_State *L, int errno);
```
A helper function to set L's global error numer, clear the stack, push nil,
and return 1.  May be used by functions to bail out while setting an error
indicator.


## stack functions
- `iptL`-functions get/set/push stack values.
- `iptT`-functions manipulate k,v-pairs of a table on top of L


### `iptL_gettable`
```c
   static table_t *iptL_gettable(lua_State *L, int index);
```
Checks whether the `L` stack value at `index` contains a userdata of type
[`LUA_IPTABLE_ID`](### LUA_IPTABLE_ID) and returns a `table_t` pointer.
Errors out to Lua if the stack value has the wrong type.


### `iptL_getaf`
```c
  static int iptL_getaf(lua_State *L, int idx, int *af);
```
Checks whether `L[idx]` is a known af_family number or name and sets `*af`
accordingly or to `AF_UNSPEC` if an unknown af_family was found.  If
`L[idx]` is missing, `*af` is not modified.  Caller decides if a missing or
unknown af_family is an error or not.


### `iptL_getbinkey`
```c
  static int iptL_getbinkey(lua_State *L, int idx, uint8_t *buf, size_t
*len);
```
Copy a binary key, either an address or a mask, at given 'idx' into given
'buf'.  'buf' size is assumed to be MAX_BINKEY.  A binary key is a byte
array [LEN | key bytes] and LEN is total length.  However, radix masks may
have set their LEN-byte equal to the nr of non-zero bytes in the array
instead.



### `iptL_getpfxstr`
```c
  const char * iptL_getpfxstr(lua_State *L, int idx, const char **, size_t *len)
```
Checks if `L[idx]` is a string and yields a const char ptr to it or NULL.
Sets len to the string length reported by Lua's stack manager.  Lua owns the
memory pointed to by the return value (no free by caller needed).


### `iptL_refpcreate`
```c
  static int iptL_refpcreate(lua_State *L);
```
Create a reference id for the lua_State given.  This allocates an int
pointer, gets a new ref_id, stores it in the allocated space and returns a
pointer to it.


### `iptL_refpdelete`
```c
  static void iptL_refpdelete(void *L, void **r);
```
Delete a value from `LUA_REGISTRYINDEX` indexed by **r (which is treated as
an **int).  Function signature is as per `purge_f_t` (see iptable.h) and
acts as the table's purge function to release user data.



### `iter_fail_f`
```c
  static int iter_fail_f(lua_State *L);
```
An iteration func that terminates any iteration.

## module functions



### `iptable.new`
```c
   static int ipt_new(lua_State *L);
```
Creates a new userdata, sets its `iptable` metatable and returns it to Lua.
It also sets the purge function for the table to
[`iptL_refpdelete`](### `iptL_refpdelete`) which frees any memory held by
the user's data once a prefix is deleted from the radix tree.


### `iptable.tobin`
Return byte array for binary key, masklength & AF for a given prefix, nil on
errors.  Note: byte array is [LEN | key-bytes], where `LEN` is the total
length of the byte array.



### `iptable.tostr`
Return string representation for a binary key, nil on errors



### `iptable.masklen`
Return the number of consecutive msb 1-bits, nil on errors.
_note: stops at the first zero bit, without checking remaining bits._


### `iptable.size`
Returns the number of hosts in a given prefix, nil on errors
- uses Lua's arithmatic (2^hostbits), since ipv6 can get large.


### `iptable.address`
Return host address, masklen and af_family for pfx; nil on errors.
```lua
 addr, mlen, af = iptable.address("10.10.10.10/24")
```


### `iptable.network`
Return network address, masklen and af_family for pfx; nil on errors.


### `iptable.neighbor`
Given a prefix, return the neighbor prefix, masklen and af_family, such that
both can be combined into a supernet with masklen -1; nil on errors.  Note
that a /0 will not have a neighbor prefix whith which it could be combined.


### `iptable.incr`
Return address, masklen and af_family by adding an offset to a pfx; If no
offset is given, increments the key by 1.  Returns nil on errors.  Note: any
mask is ignored with regards to adding the offset.


### `iptable.decr`
Return address, masklen and af_family by adding an offset to a pfx; If no
offset is given, increments the key by 1.  Returns nil on errors.  Note: any
mask is ignored with regards to adding the offset.


### `iptable.invert`
Return inverted address, masklen and af_family.
Returns nil on errors.  Note: the mask is NOT applied before invering the
address.


### `iptable.reverse`
Return a reversed address, masklen and af_family.
Returns nil on errors.  Note: the mask is NOT applied before reversing  the
address.


### `iptable.broadcast`
Return broadcast address, masklen and af_family for pfx; nil on errors.


### `iptable.mask`
```lua
  mask, af, mlen = iptable.mask(af, mlen, invert?)
```
```c
  static int ipt_mask(lua_State *L); // <-- [af, mlen, invert?]
```
Returns the mask, as a string, for the given address family `af` and mask
length `mlen`. Inverts the mask if the optional argument `invert` evaluates
to true.


### `iptable.hosts`
Iterate across host adresses in prefix pfx.

The optional incl argument defaults to false, when given & true, the network
and broadcast address will be included in the iteration results.  If pfx has
no mask, the af's max mask is used.


### `iter_hosts_f`

The iter_f for iptable.hosts(pfx), yields the next host ip until stop value
is reached.  Ignores the stack: it uses upvalues for next, stop



### `iptable.interval`
```c
  static int ipt_interval(lua_State *L) // <-- [start, stop]
```
```lua
  for pfx in iptable.interval("10.10.10.0", "10.10.10.8") do
    print(pfx)
  end
-- would print
 10.10.10.0/29
 10.10.10.8/32
```
Iterate across the prefixes that, combined, cover the address space
between the `start` & `stop` addresses given (inclusive).  Any masks in
either `start` or `stop` are ignored and both need to belong to the same
AF_family.



## instance methods


### `iptm_gc`
Garbage collect the table: free all resources
Assigned to metable's `__gc` method.


### `iptm_newindex`

Implements `t[k] = v`

If v is nil, t[k] is deleted.  Otherwise, v is stored in the lua_registry
and its ref-value is stored in the radix tree. If k is not a valid ipv4/6
prefix, cleanup and ignore the request.


### `iptm_index`
Given an index `k`:
 - do longest prefix search if `k` is a prefix without mask,
 - do an exact match if `k` is a prefix with a mask
 - otherwise, do metatable lookup for property named by `k`.


### `iptm_len`
Return the sum of the number of entries in the ipv4 and ipv6 radix trees as
the 'length' of the table.


### `iptm_tostring`
Return a string representation of the iptable instance (with iptm_counts).


### `iptm_counts`
Return both ipv4 and ipv6 iptm_counts as two numbers.


### `iter_kv`
Setup iteration across key,value-pairs in the table.  The first ipv4 or ipv6
leaf node is pushed.  The iter_pairs iterator uses nextleaf to go through
all leafs of the tree.  It will traverse ipv6 as well if we started with the
ipv4 tree first.


### `iter_kv_f`
The iter_f for __iter_kv(), yields all k,v pairs in the tree(s).

- upvalue(1) is the leaf to process.


### `lipt_itermore`
Iterate across more specific prefixes. AF_family is deduced from the
prefix given.  Note this traverses the entire tree if pfx has a /0 mask.


### `lipt_itermoref`
Iterate across more specific prefixes one at a time.
- top points to subtree where possible matches are located
- rn is the current leaf under consideration


### `t:less`
Iterate across prefixes in the tree that are less specific than pfx.
- search may include pfx itself in the results, if incl is true.
- `iter_less_f` takes (pfx, mlen, af)


### `iter_less_f`
Iterate across less specific prefixes relative to a given prefix.


### `t:masks`

Iterate across all masks used in AF_family's radix tree.
Notes:
- a mask tree stores masks in rn_key fields.
- a mask's KEYLEN == nr of non-zero mask bytes, rather LEN of byte array.
- a /0 (zeromask) is never stored in the radix mask tree (!).
- a /0 (zeromask) is stored in ROOT(0.0.0.0)'s *last* dupedkey-chain leaf.
- the AF_family cannot be deduced from the mask in rn_key.

So, the iter_f needs the AF to properly format masks for the given family
(an ipv6/24 mask would otherwise come out as 255.255.255.0) and an explicit
flag needs to be passed to iter_f that a zeromask entry is present.


### `iter_masks_f`
iter_f for `t:masks(af)`, yields all masks used in af's radix mask tree.
Masks are read-only: the Lua bindings donot (need to) interact directly with
a radix mask tree.


### `t:merge`
Iterate across groups of pfx's that may be combined, to setup just return
the first leaf of the correct AF_family's tree.


### `iter_merge`

Iterate across prefixes that may be combined.

Returns the supernet and a regular table with 2 or 3 pfx,value entries.

Caller may decide to keep only the supernet or parts of the group.  If the
supernet exists in the tree it will be present in the table as well as a
third entry.

The next node stored as upvalue before returning, must be the first node of
the next group.


### `iptL_pushitrgc`

During iteration(s), delete operations only flag radix nodes (leafs holding
a prefix) for deletion so they are not actively removed, only flagged for
deletion.  This way, the 'next leaf' node, stored as an upvalue by the
iter_xxx functions, is guaranteed to still exist on the next iteration.

Such 'inactive' leafs are still part of the tree, but are seen as absent by
regular tree operations.

The iterator garbage collector only actually removes those flagged for
deletion when there are no more iterators active (ie. itr_count reaches
zero).


### `ipt_itr_gc`
The garbage collector for iterator functions, pushed by the factory function
and executed when Lua decides to do some garbage collection.


### `t:radix`
Iterate across all nodes of all types in af's radix trees.

Only includes the radix_mask tree if the optional maskp argument is true;
The iterator will return the C-structs as Lua tables.


### `t:lipt_iterradixf`
- return current node as a Lua table or nil to stop iteration
- save next (type, node) as upvalues (1) resp. (2)


### `iptT_setfstr`
TODO: doc and move


### `iptT_setint`
TODO: doc and move


### `iptT_setkv`
set (rn->rn_key, v) on Table on top of L, based on pfx provided and its
value stored (indirectly) in the corresponding radix tree.
TODO: doc, move


### `iptL_pushrnh`
push_rdx_<node-type>'s each translating a struct to a lua table.
Will translate and push IPTF_DELETE'd nodes for completeness sake.
The lua caller may decide herself what to do with those.


### `iptL_pushrn`
TODO: doc, move


### `iptL_pushrh`
TODO: doc, move

push a radix head onto L (as a table)


### `iptL_pushrmh`
TODO: doc, move
push a radix mask head onto L (as a table)


### `iptL_pushrm`
TODO: doc, move

