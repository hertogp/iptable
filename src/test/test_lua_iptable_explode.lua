#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_lua_iptable_explode.lua
--        Usage:  busted src/test/test_lua_iptable_explode.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
describe("iptable.explode(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("has no effect on ipv4 addresses", function()
      addr, mlen, af = iptable.explode("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", addr);
    end)

    it("it does not apply a mask before exploding", function()
      addr, mlen, af = iptable.explode("10.10.10.10/24");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(24, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("explodes ipv6 all zero's", function()
      addr, mlen, af = iptable.explode("::");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(-1, mlen);
      assert.are_equal("0000:0000:0000:0000:0000:0000:0000:0000", addr);
    end)

    it("explodes regular ipv6 address", function()
      addr, mlen, af = iptable.explode("2001:acdc::/32");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(32, mlen);
      assert.are_equal("2001:acdc:0000:0000:0000:0000:0000:0000", addr);
    end)

    it("explodes intermediate ::'s", function()
      addr, mlen, af = iptable.explode("2001::acdc/32");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(32, mlen);
      assert.are_equal("2001:0000:0000:0000:0000:0000:0000:acdc", addr);
    end)

    it("explodes nothing is not needed", function()
      addr, mlen, af = iptable.explode("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/32");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(32, mlen);
      assert.are_equal("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", addr);
    end)

    it("explodes embedded ipv4's to hex digits", function()
      addr, mlen, af = iptable.explode("::ffff:11.12.13.14/128");
      assert.are_equal(iptable.AF_INET6, af);
      assert.are_equal(128, mlen);
      assert.are_equal("0000:0000:0000:0000:0000:ffff:0b0c:0d0e", addr);

    end)


    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.explode(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.explode({});
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.explode(nil);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on absent args", function()
      addr, mlen, af = iptable.explode();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

  end)
end)
