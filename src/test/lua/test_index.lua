#!/usr/bin/env lua
--
--------------------------------------------------------------------------------
--         File:  test_index.lua
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
ipt = iptable.new();

print("ipt = iptable.new()");
print("ipt[10.10.10.10] -->", ipt["10.10.10.10"]);

print("\nipt[10.10.10.0/24] = 42");
ipt["10.10.10.0/24"] = 42;

print("ipt[10.10.10.0/25] = 99");
ipt["10.10.10.0/25"] = 99;

print("\nipt[10.10.10.10] -->", ipt["10.10.10.10"]);
print("ipt[10.10.10.130] -->", ipt["10.10.10.130"]);

print("\nipt[10.10.10.0/24] = 11");
ipt["10.10.10.0/24"] = 11;
print("ipt[10.10.10.130] ->", ipt["10.10.10.130"]);

print("\nipt[10.10.10.0/24] = nil");
ipt["10.10.10.0/24"] = nil;
print("ipt[10.10.10.130] -->", ipt["10.10.10.130"]);
print("ipt[10.10.10.10] -->", ipt["10.10.10.10"]);

print("Done!");
