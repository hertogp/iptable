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

package.cpath = "./build/?.so;"

describe("iptable module: ", function()
  expose("ipt", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("has an AF_INET constant", function()
      assert.is_equal(2, iptable.AF_INET);
    end)

    it("has an AF_INET6 constant", function()
      assert.is_equal(10, iptable.AF_INET6);
    end)

    it("has an RDX_NODE_HEAD constant", function()
      assert.is_equal(0, iptable.RDX_NODE_HEAD);
    end)

    it("has an RDX_HEAD constant", function()
      assert.is_equal(1, iptable.RDX_HEAD);
    end)

    it("has an RDX_NODE constant", function()
      assert.is_equal(2, iptable.RDX_NODE);
    end)

    it("has an RDX_MASK_HEAD constant", function()
      assert.is_equal(3, iptable.RDX_MASK_HEAD);
    end)

    it("has an RDX_MASK constant", function()
      assert.is_equal(4, iptable.RDX_MASK);
    end)

  end)
end)

