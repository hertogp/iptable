#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.size(pfx): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask means 1 host", function()
      assert.are_equal(1, iptable.size("1.1.1.1"));
    end)

    it("/32 mask means 1 host", function()
      assert.are_equal(1, iptable.size("0.0.0.0/32"));
    end)

    it("/0 mask means a lot of hosts", function()
      assert.are_equal(2^32, iptable.size("0.0.0.0/0"));
    end)

    -- ipv6 may represent a lot of hosts ...
    it("62 bits is the largets working nr right now", function()
      assert.are_equal(256, iptable.size("2f::/120"));
    end)

    -- for 128 hostbits, it definitely fails!
    it("/0 mask means a lot more host for ipv6", function()
      assert.are_equal(2^128, iptable.size("2f::/0"));
    end)

  end)
end)

