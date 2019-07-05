#!/usr/bin/env lua
-------------------------------------------------------------------------------
--         File:  test_instance_methods.lua
--
--        Usage:  busted src/test/lua/test_instance_methods.lua
--
--  Description:  
--
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

F = string.format

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

      t = {}
      for p in ipt:less("1.1.1.192/26") do t[#t+1] = p end
      assert.are.equal(2, #t)

      t = {}
      for p in ipt:less("1.1.1.192/26", true) do t[#t+1] = p end
      assert.are.equal(3, #t)

      t = {}
      for p in ipt:less("1.1.1.128/25") do t[#t+1] = p end
      assert.are.equal(1, #t)

      t = {}
      for p in ipt:less("1.1.1.128/25", true) do t[#t+1] = p end
      assert.are.equal(2, #t)

      t = {}
      for p in ipt:less("1.1.1.0/24") do t[#t+1] = p end
      assert.are.equal(0, #t)

      t = {}
      for p in ipt:less("1.1.1.0/24", true) do t[#t+1] = p end
      assert.are.equal(1, #t)

      t = {}
      for p in ipt:less() do t[#t+1] = p end
      assert.are.equal(0, #t)

    end)
  end)
end)

describe("ipt:radixes(AF) ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("iterates across AF's radix nodes", function()
      ipt["1.1.1.0/24"] = 24;
      ipt["1.1.1.0/25"] = 25;
      ipt["1.1.1.128/25"] = 25;
      ipt["1.1.1.0/26"] = 26;
      ipt["1.1.1.64/26"] = 26;
      ipt["1.1.1.128/26"] = 26;
      ipt["1.1.1.192/26"] = 26;
      ipt["2f::/120"] = 643;
      ipt["3f::/90"] = 643;
      ipt["4f::/24"] = 643;

      for node in ipt:radixes(iptable.AF_INET, iptable.AF_INET6) do
        -- all tables/nodes have type & address 
        assert.is_truthy(node._TYPE_);
        assert.is_truthy(node._MEM_);

        -- check fields based on node type
        if (node._TYPE_ == iptable.RDX_NODE_HEAD) then
          -- NOTE: the function ptr values are skipped
          assert.is_truthy(node.rh);
          assert.is_truthy(node.rnh_nodes);
          assert.is_equal(3, #node.rnh_nodes);

          -- superficial check on subtables for radix nodes
          for idx, radix in ipairs(node.rnh_nodes) do
            -- each (sub)table/struct has a type & mem address
            assert.is_equal(radix._TYPE_, iptable.RDX_NODE);
            assert.is_truthy(radix._MEM_);
            assert.is_truthy(radix._ROOT_);
            if (idx == 2) then
              assert.is_truthy(radix._INTERNAL_);
            else
              assert.is_truthy(radix._LEAF_);
            end

          end

        elseif (node._TYPE_ == iptable.RDX_HEAD) then
          assert.is_truthy(node.rnh_treetop);
          assert.is_truthy(node.rnh_masks);

        elseif (node._TYPE_ == iptable.RDX_NODE) then
          assert.is_truthy(node.rn_mklist);
          assert.is_truthy(node.rn_parent);
          assert.is_truthy(node.rn_bit);
          assert.is_truthy(node.rn_bmask);
          assert.is_truthy(node.rn_flags);
          if (node._LEAF_) then
            assert.is_truthy(node.rn_key);
            assert.is_truthy(node.rn_mask);
            assert.is_truthy(node.rn_dupedkey);
          elseif (node._INTERNAL_) then
            assert.is_truthy(node.rn_offset);
            assert.is_truthy(node.rn_left);
            assert.is_truthy(node.rn_right);
          else
            assert.False("radix node neither LEAF nor INTERNAL?");
          end

        elseif (node._TYPE_ == iptable.RDX_MASK_HEAD) then
          assert.is_truthy(node.head);
          assert.is_truthy(node.mask_nodes);
          assert.is_equal(3, #node.mask_nodes);

          -- superficial check on subtables of radix nodes
          for idx, radix in ipairs(node.mask_nodes) do
            -- each (sub)table/struct has a type & mem address
            assert.is_equal(radix._TYPE_, iptable.RDX_NODE);
            assert.is_truthy(radix._MEM_);
            assert.is_truthy(radix._ROOT_);
            if (idx == 2) then
              assert.is_truthy(radix._INTERNAL_);
            else
              assert.is_truthy(radix._LEAF_);
            end
          end

        elseif (node._TYPE_ == iptable.RDX_MASK) then
          assert.is_truthy(node.rm_bit);
          assert.is_truthy(node.rm_unused);  -- yes, its there as well
          assert.is_truthy(node.rm_mklist);
          if (node._LEAF_) then
            assert.is_truthy(node.rm_leaf);
          else
            assert.is_truthy(node.rm_mask);
          end
          -- assert.is_truthy(node.rm_refs);
        else
          mu_false("unexpected radix node type");
        end
      end

    end)
  end)
end)
