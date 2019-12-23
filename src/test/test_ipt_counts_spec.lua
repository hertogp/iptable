#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

F = string.format

describe("iptable object length: ", function()

  expose("ipt obj: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("counts ipv4 prefixes", function()
      ipt["10.10.10.10/24"] = 24;
      assert.is_equal(1, #ipt);

      ipt["11.11.11.11/24"] = 42;
      assert.is_equal(2, #ipt);
    end)

    it("counts ipv6 prefixes", function()
      ipt = iptable.new()
      ipt["2f::/64"] = 64;
      ipt["2f::/104"] = 104;
      ipt["3f::/14"] = 14;
      assert.is_equal(3, #ipt);

      local v4, v6 = ipt:counts();
      assert.is_equal(0, v4);
      assert.is_equal(3, v6);
    end)

    it("counts both ipv4 and ipv6 prefixes", function()
      ipt = iptable.new()
      ipt["10.10.10.10/24"] = 24;
      ipt["11.11.11.11/24"] = 42;
      ipt["2f::/64"] = 64;
      ipt["2f::/104"] = 104;
      ipt["3f::/14"] = 14;
      assert.is_equal(5, #ipt);

    end)
  end)
end)

