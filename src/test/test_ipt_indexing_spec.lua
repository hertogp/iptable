#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

F = string.format

describe("ipt obj indexing: ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);
    ipt["10.10.10.0/26"] = 26;
    ipt["10.10.10.0/24"] = 24;  -- omit the /25 mask

    it("does lpm for host address (without mask)", function()
      assert.are_equal(26, ipt["10.10.10.1"]);
      assert.are_equal(24, ipt["10.10.10.64"]);
    end)

    it("does exact match for prefixes with a mask", function()
      assert.are_equal(24, ipt["10.10.10.32/24"]);
      assert.are_equal(nil, ipt["10.10.10.64/25"]);
      assert.are_equal(nil, ipt["10.10.10.0/25"]);
    end)

  end)
end)

describe("iptable object interface", function() 
  expose("of iptable instance:", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("new table must be empty", function()
      local v4, v6 = ipt:counts();
      assert.are_equal(0, v4);
      assert.are_equal(0, v6);
    end)

    it("assignment", function()
      ipt["10.10.10.0/24"] = 42;
      assert.are_equal(42, ipt["10.10.10.0/24"]);
      assert.are_equal(42, ipt["10.10.10.10/24"]);
      assert.are_equal(42, ipt["10.10.10.10"]);
      assert.are_equal(1, ipt:counts());
      assert.are_equal(0, select(2, ipt:counts()));
    end)

    it("assignment uses exact match", function()
      ipt["10.10.10.0/24"] = 99;
      assert.are_equal(99, ipt["10.10.10.129/24"]);
      assert.are_equal(99, ipt["10.10.10.129"]);
      assert.are_equal(99, ipt["10.10.10.255"]);
    end)

    it("more specific", function()
      ipt["10.10.10.0/25"] = 99;
      assert.are_equal(99, ipt["10.10.10.10/25"]);
      assert.are_equal(99, ipt["10.10.10.10"]);
    end)

    it("more specific", function()
      ipt["10.10.10.0/24"] = 11;
      assert.are_equal(11, ipt["10.10.10.129/24"]);
    end)

    it("assigning nil deletes entry", function()
      ipt["10.10.10.0/24"] = nil;
      assert.are_equal(nil, ipt["10.10.10.129/24"]);
    end)

    it("unknown index yields nil", function()
      assert.are_equal(nil, ipt.not_a_field_in_table);
    end)

    it("unknown index yields nil", function()
      assert.are_equal(nil, ipt[""]);
    end)

    it("unknown index yields nil", function()
      assert.are_equal(nil, ipt["10e"]);
    end)

    it("unknown index yields nil", function()
      ipt.a_really_long_property_name = 42;
      assert.are_equal(nil, ipt.a_really_long_property_name);
    end)

  end)
end)
