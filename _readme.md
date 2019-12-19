---
author: hertogp <git.hertogp@gmail.com>
title: iptable
imagine.shebang.im_out: ocb,stdout
...

# iptable

A Lua binding to a `iptable.c`, which is a thin wrapper around
[radix.c](https://raw.githubusercontent.com/freebsd/freebsd/master/sys/net/radix.c)
[radix.h](https://raw.githubusercontent.com/freebsd/freebsd/master/sys/net/radix.h)
from the [FreeBsd](https://www.freebsd.org/) project.

`iptable` provides some convenience functions to work with ip addresses (both
ipv4 and ipv6) as well as a longest prefix matching (Lua) table.

## Requirements and limitations

`iptable` is developed on a linux machine and support for other OS's is
non-existent.  The following is currently used to build iptable:

```{.shebang im_out=stdout im_log=4}
#!/bin/bash
echo "- $(lua -v)"
echo "- $(lsb_release -sirc | tr '\n' ' ')"
echo "- $(gcc --version | head -n 1)"
echo "- $(make -v | head -n 1)"
```

Additionally for testing and documentation:

```{.shebang im_out=stdout}
#!/bin/bash
echo "- $(valgrind --version)"
echo "- busted $(busted --version)"
echo "- $(pandoc --version | head -n 1)"
```

## Installation

Install using make.
```
cd ~/installs
git clone https://github.com/hertogp/iptable.git
cd iptable
make test
sudo -H make install
# or
make local_install    # copies to ~/.luarocks/lib/lua/5.3
```

Install using luarocks

- todo.

## Usage

An iptable.new() yields a Lua table with modified indexing behaviour:

- the table utilizes 2 separate radix trees for ipv4 and ipv6 respectively
- the table handles both ipv4 or ipv6 keys transparently
- if a key is not an ipv4 or ipv6 prefix/address it is *ignored*
- when storing data, masks are always applied first to the key
- when storing data, missing masks default to the AF's maximum mask
- storing data is always based on an exact match which includes the mask
- retrieving data for a prefix, is also based on an exact match
- retrieving data via an ip address uses a longest prefix match
- table entry counts or prefix size functions are accurate upto 2^52

Example usage:

```lua
ipt = require"iptable".new()

ipt["10.10.10.0/24"] = {c=0}          -- store anything in the table
ipt["10.10.10.10"] = false            -- stores to ipt["10.10.10.10/32"]
ipt["11.11.11.11/24"] = true          -- stores to ipt["11.11.11.0/24"]
ipt["acdc:1974::/32"] = "Jailbreak"   -- goes into separate radix tree
ipt[1] = 42                           -- ignored: ipt[1] -> nil
#ipt                                  -- 4 entries in total
ipt.counts()                          -- 3  1  (ipv4 and ipv6 counts)

for k,v in pairs(ipt) do              -- 10.10.10.0/24    table 0x...
    print(k,v)                        -- 10.10.10.10/32   false
                                      -- 11.11.11.0/24    true
end                                   -- acdc:1974::/32   Jailbreak
```

# Quick reference

```lua

iptable = require "iptable"

-- Module constants

iptable.AF_INET  --  2
iptable.AF_INET6 -- 10

-- Module functions

prefix = "10.10.10.0/24"                       -- ipv4/6 address or prefix

addr,  mlen, af = iptable.address(prefix)      -- 10.10.10.0   24  2
netw,  mlen, af = iptable.network(prefix)      -- 10.10.10.0   24  2
bcast, mlen, af = iptable.broadcast(prefix)    -- 10.10.10.255 24  2
neigb, mlen, af = iptable.neighbor(prefix)     -- 10.10.11.0   24  2

next,  mlen, af = iptable.incr(prefix)         -- 10.10.10.1   24  2
next,  mlen, af = iptable.incr(prefix, 257)    -- 10.10.11.1   24  2
prev,  mlen, af = iptable.decr(prefix)         -- 10.10.9.255  24  2
prev,  mlen, af = iptable.decr(prefix, 257)    -- 10.10.8.255  24  2

mask = iptable.mask(iptable.AF_INET, 24)       -- 255.255.255.0
size = iptable.size(prefix)                    -- 256

binkey = iptable.tobin("255.255.255.0")        -- byte string 05:ff:ff:ff:00
prefix = iptable.tostr(binkey)                 -- 255.255.255.0
msklen = iptable.masklen(binkey)               -- 24
ipt    = iptable.new()                         -- longest prefix match table

-- table functions

ipt:counts()                                   -- 0 0 (ipv4_count ipv6_count)
for k,v in pairs(ipt) do ... end               -- iterate across k,v-pairs
for k,v in ipt:more(prefix [,true]) ... end    -- iterate across more specifics
for k,v in ipt:less(prefix [,true]) ... end    -- iterate across less specifics
for k,v in ipt:masks(prefix [,true]) ... end   -- iterate across masks used
for k,g in ipt:merge(prefix [,true]) ... end   -- iterate across combinable pfx's
for rdx in ipt:radixes(af [,true]) ... end    -- dumps all radix nodes in tree

-- note: use `true` as 2nd (optional boolean) argument to:
--> include search `prefix` itself in search results if found, or
--> to also dump the radix nodes from the (separate) radix mask tree
```


# Documentation

See also the `doc` directory on [github](https://github.com/hertogp/iptable).

## module constants

```{.shebang .lua im_out=stdout im_log=4}
#!/usr/bin/env lua
iptable = require"iptable"
F = string.format

for k,v in pairs(iptable) do
    if type(v) == "number" then
        print(F("iptable.%s  %4s", k, v))
    end
end
```

## module functions

Requiring `iptable` yields an object with module level functions.

```lua
iptable = require "iptable"
```

### `iptable.address(prefix)`

Returns the host address, mask length and address family given prefix.

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.10.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

ip, mlen, af = iptable.address(pfx4)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.address(pfx6)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.network(prefix)`

Returns the network address, mask length and address family for given prefix.

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.10.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

ip, mlen, af = iptable.network(pfx4)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.network(pfx6)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.broadcast(prefix)`

Returns the broadcast address, mask length and address family for given prefix.

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.10.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

ip, mlen, af = iptable.broadcast(pfx4)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.broadcast(pfx6)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.incr(prefix [,offset])`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.10.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

ip, mlen, af = iptable.incr(pfx4)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.incr(pfx4, 10)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.incr(pfx6, 5)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.decr(prefix [, offset])`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.10.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

ip, mlen, af = iptable.decr(pfx4, 1)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

ip, mlen, af = iptable.decr(pfx6, 1)
print(string.format("-- ip %s, mlen %s, af %s", ip, mlen, af))

print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.interval(start, stop)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"

for pfx in iptable.interval("10.10.10.0", "10.10.10.12") do
    print("-- ", pfx)
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.mask(af, mlen [, invert])`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"

print(iptable.mask(2, 19))
print(iptable.mask(2, 19, true))

print(iptable.mask(10, 91))
print(iptable.mask(10, 91, true))


print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.neighbor(prefix)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

print(iptable.neighbor("10.10.0.0/19"))
print(iptable.neighbor("10.10.32.0/19"))
print(iptable.neighbor("10.10.10.255"))
print(iptable.neighbor("0.0.0.0/0"))      -- nothing larger than this
print(iptable.neighbor(pfx6))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.size(...)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

print(iptable.size("10.10.10.0/24"))
print(iptable.size("10.10.0.0/31"))
print(iptable.size(pfx6))
print(iptable.size("2001::/0"))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `iptable.tobin(prefix)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "10.10.0.0/19"
pfx6 = "2001:0db8:85a3:0000:0000:8a2e:0370:700/120"

bin2str = function(buf)
  local s = ""
  local len = buf:byte(1)
  for i = 1, len, 1 do
    s = string.format("%s:%02x", s, buf:byte(i));
  end
  return s:sub(2) -- skip leading ':'
end

bin4, mlen, af = iptable.tobin(pfx4)
bin6, mlen, af = iptable.tobin(pfx6)

print(bin2str(bin4))
print(bin2str(bin6))

print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.masklen(binary_key)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "255.255.253.0"
pfx6 = "ffff:fffe::"

bin2str = function(buf)
  local s = ""
  local len = buf:byte(1)
  for i = 1, len, 1 do
    s = string.format("%s:%02x", s, buf:byte(i));
  end
  return s:sub(2) -- skip leading ':'
end

bin4, mlen4, af4 = iptable.tobin(pfx4)
bin6, mlen6, af6 = iptable.tobin(pfx6)

print(iptable.masklen(bin4), "consecutive 1's in:", bin2str(bin4))
print(iptable.masklen(bin6), "consecutive 1's in:", bin2str(bin6))

print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.tostr(binary_key)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require"iptable"
pfx4 = "255.255.253.0"
pfx6 = "ffff:fffe::"

bin2str = function(buf)
  local s = ""
  local len = buf:byte(1)
  for i = 1, len, 1 do
    s = string.format("%s:%02x", s, buf:byte(i));
  end
  return s:sub(2) -- skip leading ':'
end

bin4, mlen4, af4 = iptable.tobin(pfx4)
bin6, mlen6, af6 = iptable.tobin(pfx6)

print(iptable.tostr(bin4), " == ", pfx4)
print(iptable.tostr(bin6), " == ", pfx6)

print(string.rep("-", 35))

---------- PRODUCES --------------
```


### `iptable.new()`

Constructor method that returns a new ipv4,ipv6 lookup table.  Use it as a
regular table with modified indexing:

- *exact*  indexing is used for assignments or when the index has a masklength
- *longest prefix match* if indexed with a bare host address


## table functions

### Basic operations

```{.shebang .lua}
#!/usr/bin/env lua
acl = require"iptable".new()

acl["10.10.10.0/24"] = true
acl["10.10.10.8/30"] = false

print("--> 1 exact match for prefix 10.10.10.0/24  ->", acl["10.10.10.0/24"])
print("--> 2 longest prefix match for 10.10.10.9   ->", acl["10.10.10.9"])
print("--> 3 longest prefix match for 10.10.10.100 ->", acl["10.10.10.100"])
print("--> 4 exact match for prefix 10.10.10.10/30 ->", acl["10.10.10.10/30"])
print(string.format("--> 5 acl has %s entries", #acl))

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:more(prefix)`

```{.shebang .lua}
#!/usr/bin/env lua
ipt = require"iptable".new()

ipt["10.10.0.0/16"] = 1
ipt["10.10.9.0/24"] = 2
ipt["10.10.10.0/24"] = 3
ipt["10.10.10.0/25"] = 4
ipt["10.10.10.0/26"] = 5
ipt["10.10.10.128/30"] = 6

-- search more specifics only

for pfx in ipt:more("10.10.10.0/24") do
    print("-- exclusive search ->", pfx)
end
print()

-- search includes starting search prefix

for pfx in ipt:more("10.10.10.0/24", true) do
    print("-- inclusive search ->", pfx)
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:less(prefix)`

```{.shebang .lua}
#!/usr/bin/env lua
ipt = require"iptable".new()

ipt["10.10.0.0/16"] = 1
ipt["10.10.9.0/24"] = 2
ipt["10.10.10.0/24"] = 3
ipt["10.10.10.0/25"] = 4
ipt["10.10.10.0/26"] = 5
ipt["10.10.10.128/30"] = 6

-- search less specifics only

for pfx in ipt:less("10.10.10.0/25") do
    print("-- exclusive search ->", pfx)
end
print()

-- search includes starting search prefix

for pfx in ipt:less("10.10.10.0/25", true) do
    print("-- inclusive search ->", pfx)
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:merge(af)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require "iptable"
ipt = iptable.new()

ipt["10.11.0.0/16"] = 1
ipt["10.10.9.0/24"] = 2
ipt["10.10.10.0/24"] = 3
ipt["10.10.10.0/25"] = 4
ipt["10.10.10.128/25"] = 5
ipt["10.10.10.0/30"] = 6
ipt["10.10.10.4/30"] = 7

-- find adjacent prefixes

for supernet, grp in ipt:merge(iptable.AF_INET) do
    print(string.format("-- supernet %s contains:", supernet))
    for subnet, val in pairs(grp) do
        print(string.format("   -- %s -> %s", subnet, val))
    end
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:masks(af)`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require "iptable"
ipt = iptable.new()

ipt["10.10.0.0/16"] = 1
ipt["10.10.9.0/24"] = 2
ipt["10.10.10.0/24"] = 3
ipt["10.10.10.0/25"] = 4
ipt["10.10.10.0/26"] = 5
ipt["10.10.10.128/30"] = 6

-- iterate across masks in the trie
for pfx in ipt:masks(iptable.AF_INET) do
    print("-- mask ->", pfx)
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:counts()`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require "iptable"
ipt = iptable.new()

ipt["10.10.0.0/16"] = 1
ipt["10.10.9.0/24"] = 2
ipt["10.10.10.0/24"] = 3
ipt["10.10.10.0/25"] = 4
ipt["10.10.10.0/26"] = 5
ipt["10.10.10.128/30"] = 6
ipt["2001::dead:beef/120"] = 1
ipt["2002::dead:beef/120"] = 2
ipt["2003::dead:beef/120"] = 3

af4, af6 = ipt:counts()

print("-- num of ipv4 prefixes", af4)
print("-- num of ipv6 prefixes", af6)

print(string.rep("-", 35))

---------- PRODUCES --------------
```

### `ipt:radixes(af[, masktree])`

```{.shebang .lua}
#!/usr/bin/env lua
iptable = require "iptable"
ipt = iptable.new()

ipt["10.10.0.0/16"] = 1
ipt["2003::dead:beef/120"] = 1

-- dump radix nodes in the radix trie
for rdx in ipt:radixes(iptable.AF_INET | iptable.AF_INET6) do
    print("-- tree exclusive", rdx._NAME_)
end
print()

-- also include the mask-tree
for rdx in ipt:radixes(iptable.AF_INET | iptable.AF_INET6, true) do
    print("-- tree inclusive", rdx._NAME_)
end

print(string.rep("-", 35))

---------- PRODUCES --------------
```



# Examples:

## Large tree graphs

### Graph an IPv4 tree

```{.shebang .lua im_out=ocb,img}
#!/usr/bin/env lua

iptable = require "iptable"
dotify = require "src.lua.ipt2dot"
ipt = iptable.new()

ipt["10.10.10.0/24"] = 1
ipt["10.10.10.0/25"] = 2
ipt["10.10.10.128/25"] = 3
ipt["10.10.10.128/26"] = 4
ipt["11.11.11.0/24"] = 2


imgfile = arg[1]
dotfile = imgfile:gsub("...$", "dot")
dottext = dotify(ipt, iptable.AF_INET)

fh = io.open(dotfile, "w")
fh:write(table.concat(dottext, "\n"))
fh:close()

os.execute(string.format("dot -Tpng %s -o %s", dotfile, imgfile))
print(string.rep("-",35))

---------- PRODUCES --------------
```

### Graph an IPv6 tree

```{.shebang .lua im_out=ocb,img}
#!/usr/bin/env lua

iptable = require "iptable"
dotify = require "src.lua.ipt2dot"
ipt = iptable.new()

ipt["acdc:1974::/32"] = "Can I sit next to you?"
ipt["acdc:1976::/32"] = "Jailbreak"
ipt["acdc:1979::/32"] = "Highway to hell"
ipt["acdc:1980::/32"] = "Touch too much"


imgfile = arg[1]
dotfile = imgfile:gsub("...$", "dot")
dottext = dotify(ipt, iptable.AF_INET6)

fh = io.open(dotfile, "w")
fh:write(table.concat(dottext, "\n"))
fh:close()

os.execute(string.format("dot -Tpng %s -o %s", dotfile, imgfile))
print(string.rep("-",35))

---------- PRODUCES --------------
```

## Small(er) tree graphs

### Graph an IPv4 tree

```{.shebang .lua im_out=ocb,img}
#!/usr/bin/env lua

iptable = require "iptable"
dotify = require "src.lua.ipt2smalldot"
ipt = iptable.new()

ipt["10.10.10.0/24"] = 1
ipt["10.10.10.0/25"] = 2
ipt["10.10.10.128/25"] = 3
ipt["10.10.10.128/26"] = 4
ipt["11.11.11.0/24"] = 2


imgfile = arg[1]
dotfile = imgfile:gsub("...$", "dot")
dottext = dotify(ipt, iptable.AF_INET)

fh = io.open(dotfile, "w")
fh:write(table.concat(dottext, "\n"))
fh:close()

os.execute(string.format("dot -Tpng %s -o %s", dotfile, imgfile))
print(string.rep("-",35))

---------- PRODUCES --------------
```

### Graph an IPv6 tree

```{.shebang .lua im_out=ocb,img}
#!/usr/bin/env lua

iptable = require "iptable"
dotify = require "src.lua.ipt2smalldot"
ipt = iptable.new()

ipt["acdc:1974::/32"] = "Can I sit next to you?"
ipt["acdc:1976::/32"] = "Jailbreak"
ipt["acdc:1979::/32"] = "Highway to hell"
ipt["acdc:1980::/32"] = "Touch too much"


imgfile = arg[1]
dotfile = imgfile:gsub("...$", "dot")
dottext = dotify(ipt, iptable.AF_INET6)

fh = io.open(dotfile, "w")
fh:write(table.concat(dottext, "\n"))
fh:close()

os.execute(string.format("dot -Tpng %s -o %s", dotfile, imgfile))
print(string.rep("-",35))

---------- PRODUCES --------------
```


## Minify list of prefixes

```{.shebang .lua im_out=ocb,stdout,stderr}
#!/usr/bin/env lua
iptable = require "iptable"

-- fill a table with list of prefixes
ipt = iptable.new()
ipt["10.10.10.0/25"] = true
ipt["10.10.10.128/25"] = true
ipt["10.10.11.0/25"] = true
ipt["10.10.11.128/25"] = true
ipt["11.11.11.0"] = true
ipt["11.11.11.1"] = true
ipt["11.11.11.2"] = true
ipt["11.11.11.3"] = true

for k,_ in pairs(ipt) do
    print("-- original ->", k)
end
print()

changed = true
while (changed) do
    changed = false
    for supernet, grp in ipt:merge(iptable.AF_INET) do
        for subnet, _ in pairs(grp) do
            ipt[subnet] = nil
            changed = true
         end
         ipt[supernet] = true
    end
end

for prefix, _ in pairs(ipt) do
    for subnet, _ in ipt:more(prefix, false) do
        ipt[subnet] = nil
    end
end

for k, _ in pairs(ipt) do
    print("-- minified ->", k)
end

print(string.rep("-",35))

---------- PRODUCES --------------
```

