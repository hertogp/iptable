#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

describe("iptable.mask(af, num)", function()

  expose("module: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("handles ipv4 max (inv)mask", function()
      assert.equal("255.255.255.255", iptable.mask(iptable.AF_INET, 32));
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, 32, true));
    end)

    it("handles ipv4 min (inv)mask", function()
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, 0));
      assert.equal("0.0.0.0", iptable.mask(iptable.AF_INET, -0));
    end)

    it("handles ipv4 regular (inv)masks", function()
      assert.equal("255.255.255.254", iptable.mask(iptable.AF_INET, 31));
      assert.equal("0.0.0.1", iptable.mask(iptable.AF_INET, 31, true));

      assert.equal("255.255.255.252", iptable.mask(iptable.AF_INET, 30));
      assert.equal("0.0.0.3", iptable.mask(iptable.AF_INET, 30, true));

      assert.equal("255.255.255.128", iptable.mask(iptable.AF_INET, 25));
      assert.equal("0.0.0.127", iptable.mask(iptable.AF_INET, 25, true));

      assert.equal("255.255.255.0", iptable.mask(iptable.AF_INET, 24));
      assert.equal("0.0.0.255", iptable.mask(iptable.AF_INET, 24,true));

      assert.equal("255.255.0.0", iptable.mask(iptable.AF_INET, 16));
      assert.equal("0.0.255.255", iptable.mask(iptable.AF_INET, 16, true));

      assert.equal("255.0.0.0", iptable.mask(iptable.AF_INET, 8));
      assert.equal("0.255.255.255", iptable.mask(iptable.AF_INET, 8, true));

      assert.equal("128.0.0.0", iptable.mask(iptable.AF_INET, 1));
      assert.equal("127.255.255.255", iptable.mask(iptable.AF_INET, 1, true));
    end)

  end)
end)
