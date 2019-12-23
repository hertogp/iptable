#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_create.lua
-------------------------------------------------------------------------------

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

  end)
end)

