#!/usr/bin/env lua
--
-------------------------------------------------------------------------------
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
-------------------------------------------------------------------------------
--

package.cpath = "./build/?.so;"..package.cpath

describe("require iptable", function()
  expose("iptable", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("tests requiring the module", function()
      iptable = require("iptable");
      assert.is_truthy(iptable);
    end)

    it("tests creating an iptable", function()
      ipt = iptable.new()
      assert.is_truthy(ipt);
    end)

  end)
end)

