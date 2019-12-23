#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"

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

      for node in ipt:radixes("AF_INET6") do
        -- all tables/nodes have type & address 
        assert.is_truthy(node._NAME_);
        assert.is_truthy(node._MEM_);
        -- check fields based on node type
        if (node._NAME_ == "RADIX_NODE_HEAD") then
          -- NOTE: the function ptr values are skipped
          assert.is_truthy(node.rh);
          assert.is_truthy(node.rnh_nodes);
          assert.is_equal(3, #node.rnh_nodes);

          -- superficial check on subtables for radix nodes
          for idx, radix in ipairs(node.rnh_nodes) do
            -- each (sub)table/struct has a type & mem address
            assert.is_equal(radix._NAME_, "RADIX_NODE");
            assert.is_truthy(radix._MEM_);
            assert.is_truthy(radix._ROOT_);
            if (idx == 2) then
              assert.is_truthy(radix._INTERNAL_);
            else
              assert.is_truthy(radix._LEAF_);
            end

          end

        elseif (node._NAME_ == "RADIX_HEAD") then
          assert.is_truthy(node.rnh_treetop);
          assert.is_truthy(node.rnh_masks);

        elseif (node._NAME_ == "RADIX_NODE") then
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

        elseif (node._NAME_ == "RADIX_MASK_HEAD") then
          assert.is_truthy(node.head);
          assert.is_truthy(node.mask_nodes);
          assert.is_equal(3, #node.mask_nodes);

          -- superficial check on subtables of radix nodes
          for idx, radix in ipairs(node.mask_nodes) do
            -- each (sub)table/struct has a type & mem address
            assert.is_equal(radix._NAME_, "RADIX_NODE");
            assert.is_truthy(radix._MEM_);
            assert.is_truthy(radix._ROOT_);
            if (idx == 2) then
              assert.is_truthy(radix._INTERNAL_);
            else
              assert.is_truthy(radix._LEAF_);
            end
          end

        elseif (node._NAME_ == "RADIX_MASK") then
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
          assert.False(F("unexpected radix node name %q", node._NAME_));
        end
      end

    end)
  end)
end)
