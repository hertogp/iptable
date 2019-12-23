#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.address(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask -> address is itself", function()
      addr, mlen, af = iptable.address("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", addr);
    end)

    it("max mask -> address is itself", function()
      addr, mlen, af = iptable.address("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("zero mask -> address is still itself", function()
      addr, mlen, af = iptable.address("10.10.10.10/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("normal mask -> address is still address", function()
      addr, mlen, af = iptable.address("10.10.10.10/8");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(8, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("yields nils when args absent", function()
      addr, mlen, af = iptable.address();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils when args non-string", function()
      addr, mlen, af = iptable.address(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils for illegal prefixes", function()
      addr, mlen, af = iptable.address("10.10.10.10/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, addr);
    end)

    it("yields nils for illegal prefixes", function()
      addr, mlen, af = iptable.address("10.10.10.10/33");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)


  end)
end)
