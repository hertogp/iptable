#!/usr/bin/env lua
--
--------------------------------------------------------------------------------
--         File:  test_create.lua
--
--        Usage:  ./test_create.lua
--
--  Description:  
--
--      Options:  ---
-- Requirements:  ---
--         Bugs:  ---
--        Notes:  ---
--       Author:  YOUR NAME (), <>
-- Organization:  
--      Version:  1.0
--      Created:  01-06-19
--     Revision:  ---
--------------------------------------------------------------------------------
--

package.cpath = "./build/?.so;"..package.cpath

iptable = require("iptable");
print(string.rep("-", 20), "iptable.new\n");
ipt = iptable.new();

print("\n" ..string.rep("-", 20), "print(ipt[..])\n");
print("ipt[] ->", ipt["10.10.10.10/24"]);

print("\n"..string.rep("-", 20), "ipt[..] = 42\n");
ipt["10.10.10.10/24"] = 42;


print("\n"..string.rep("-", 20), "ipt:set(.., 42)\n");
ipt:set("10.10.10.10/24", 42);

print("\n"..string.rep("-", 20), "ipt:get(..)\n");
ipt:get("10.10.10.10/24");


print("Done!");
