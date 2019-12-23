#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_lua_iptable_broadcast.lua
--        Usage:  busted src/test/test_lua_iptable_broadcast.lua
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
describe("iptable.broadcast(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask -> broadcast is itself", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", addr);
    end)

    it("max mask -> broadcast is itself", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);
      assert.are_equal("10.10.10.10", addr);
    end)

    it("zero mask -> broadcast is all broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);
      assert.are_equal("255.255.255.255", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/30");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(30, mlen);
      assert.are_equal("10.10.10.11", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.10.10.10/8");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(8, mlen);
      assert.are_equal("10.255.255.255", addr);
    end)

    it("normal mask -> broadcast is subnet broadcast", function()
      addr, mlen, af = iptable.broadcast("10.11.12.13/27");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(27, mlen);
      assert.are_equal("10.11.12.31", addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast({});
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on non-string args", function()
      addr, mlen, af = iptable.broadcast(nil);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

    it("yields nils on absent args", function()
      addr, mlen, af = iptable.broadcast();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);
      assert.are_equal(nil, addr);
    end)

  end)
end)
