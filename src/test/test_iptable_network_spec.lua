#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.network(): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("no mask -> network is itself", function()
      netw, mlen, af = iptable.network("10.10.10.10");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(-1, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", netw);
    end)

    it("max mask -> network is itself", function()
      netw, mlen, af = iptable.network("10.10.10.10/32");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(32, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.10", netw);
    end)

    it("zero mask -> network is all zeros", function()
      netw, mlen, af = iptable.network("10.10.10.10/0");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(0, mlen);  -- -1 means no mask was provided
      assert.are_equal("0.0.0.0", netw);
    end)

    it("normal mask -> network address", function()
      netw, mlen, af = iptable.network("10.10.10.10/8");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(8, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.0.0.0", netw);
    end)

    it("normal mask -> network address", function()
      netw, mlen, af = iptable.network("10.10.10.10/30");
      assert.are_equal(iptable.AF_INET, af);
      assert.are_equal(30, mlen);  -- -1 means no mask was provided
      assert.are_equal("10.10.10.8", netw);
    end)

    it("yields nils when args absent", function()
      netw, mlen, af = iptable.network();
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils when args non-string", function()
      netw, mlen, af = iptable.network(true);
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils for illegal prefixes", function()
      netw, mlen, af = iptable.network("10.10.10.10/-1");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

    it("yields nils for illegal prefixes", function()
      netw, mlen, af = iptable.network("10.10.10.10/33");
      assert.are_equal(nil, af);
      assert.are_equal(nil, mlen);  -- -1 means no mask was provided
      assert.are_equal(nil, netw);
    end)

  end)
end)
