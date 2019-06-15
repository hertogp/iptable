#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_instance_methods.lua
--
--        Usage:  busted src/test/lua/test_instance_methods.lua
--
--  Description:  
--
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"..package.cpath

describe("iptable instance methods: ", function()
  expose("ipt", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);


  end)
end)


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


describe("iptable iteration: ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("yields ipv4 k,v-pairs", function()
      ipt["10.10.10.10/24"] = 24;
      ipt["11.11.11.11/24"] = 42;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(2, cnt);
      assert.is_equal(24, t["10.10.10.0/24"]);
      assert.is_equal(42, t["11.11.11.0/24"]);

    end)

    it("yields ipv6 k,v-pairs", function()
      ipt["10.10.10.10/24"] = nil; -- delete entries
      ipt["11.11.11.11/24"] = nil;
      ipt["2f::/128"] = 128;       -- only two ipv6 entries
      ipt["4b:aa::/64"] = 64;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(2, cnt);
      assert.is_equal(128, t["2f::/128"]);
      assert.is_equal(64, t["4b:aa::/64"]);
    end)

    it("yields both ipv4 & ipv6 k,v-pairs", function()
      ipt["10.10.10.10/24"] = 24; -- delete entries
      ipt["11.11.11.11/24"] = 42;
      ipt["2f::/128"] = 128;       -- only two ipv6 entries
      ipt["4b:aa::/64"] = 64;

      local cnt = 0;
      t = {}
      for k, v in pairs(ipt) do
        cnt = cnt + 1;
        t[k] = v;
      end
      assert.is_equal(4, cnt);
      assert.is_equal(24, t["10.10.10.0/24"]);
      assert.is_equal(42, t["11.11.11.0/24"]);
      assert.is_equal(128, t["2f::/128"]);
      assert.is_equal(64, t["4b:aa::/64"]);
    end)
  end)
end)


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

describe("iptable tostring: ", function()

  expose("ipt obj: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("shows both ipv4 and ipv6 counts", function()
      ipt["1.1.1.1"] = 1;
      ipt["2.2.2.2"] = 2;
      ipt["3.3.3.3"] = 2;
      ipt["2f::"] = 1;
      ipt["2f::/16"] = 2;
      local str = string.format("%s", ipt);
      assert.is_equal("iptable{#ipv4=3, #ipv6=2}", str);
    end)
  end)
end)

describe("ipt:more(pfx) ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("iterates across more specific prefixes", function()
      ipt["1.1.1.0/24"] = 24;
      ipt["1.1.1.0/25"] = 25;
      ipt["1.1.1.128/25"] = 25;
      ipt["1.1.1.0/26"] = 26;
      ipt["1.1.1.32/26"] = 26;
      ipt["1.1.1.64/26"] = 26;
      ipt["1.1.1.96/26"] = 26;
      pending("ipt:more(pfx) yet to be implemented");
    end)
  end)
end)

describe("ipt:less(pfx) ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("iterates across less specific ipv4 prefixes", function()
      ipt["1.1.1.0/24"] = 24;
      ipt["1.1.1.0/25"] = 25;
      ipt["1.1.1.128/25"] = 25;
      ipt["1.1.1.0/26"] = 26;
      ipt["1.1.1.64/26"] = 26;
      ipt["1.1.1.128/26"] = 26;
      ipt["1.1.1.192/26"] = 26;
      pending("ipt:less(pfx) yet to be implemented");
      -- cnt = 0;
      -- for pfx in ipt:less("1.1.1.200/26") do
      --   cnt = cnt + 1
      -- end
      -- assert.equal(2, cnt); -- ie 1.1.1.128/25 and 1.1.1.0/24
    end)
  end)
end)
