#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
-------------------------------------------------------------------------------

package.cpath = "./build/?.so;"
package.path = "./src/lua/?.lua"

F = string.format

describe("ipt:supernets(): ", function()

  expose("iptable", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("finds prefixes that are able to supernets", function()
      local cnt = 0
      local ipt = iptable.new();
      assert.is_truthy(ipt);

      ipt["1.2.3.0/24"] = 1     -- sole supernet entry
      ipt["1.2.3.0/25"] = 2     -- pair w/ the next entry
      ipt["1.2.3.128/25"] = 4
      ipt["1.2.3.0/26"] = 8     -- pair w/ the next entry
      ipt["1.2.3.64/26"] = 16
      ipt["1.2.3.128/26"] = 32  -- pair w/ the next entry
      ipt["1.2.3.192/26"] = 64

      for p, t in ipt:supernets(iptable.AF_INET) do cnt = cnt + 1 end
    end)

    it("is safe to delete both the super and paired-keys", function()
      local ipt = iptable.new();
      assert.is_truthy(ipt);

      ipt["1.2.3.0/24"] = 1     -- sole supernet entry

      ipt["1.2.3.0/25"] = 2     -- pair w/ the next entry
      ipt["1.2.3.128/25"] = 4

      ipt["1.2.3.0/26"] = 8     -- pair w/ the next entry
      ipt["1.2.3.64/26"] = 16

      ipt["1.2.3.128/26"] = 32  -- pair w/ the next entry
      ipt["1.2.3.192/26"] = 64
      local checksum = 0 -- calculate the sum of all values
      for k,v in pairs(ipt) do checksum = checksum + v end

      -- rearrange the tree
      for p, t in ipt:supernets(iptable.AF_INET) do
        local sum = 0
        for k, v in pairs(t) do
          ipt[k] = nil   -- delete the subnets (and possibly supernet if any)
          sum = sum + v  -- sum their values
        end
        ipt[p] = sum     -- set supernet value to the calculated sum
      end
      -- recalculate the total sum, it should be the same
      local sum = 0
      for k,v in pairs(ipt) do sum = sum + v end
      assert.is_equal(checksum, sum)
    end)

    it("handles deletions while merging", function()
      local ipt = iptable.new()
      assert.is_truthy(ipt)

      ipt = iptable.new()
      ipt["10.10.10.0/25"] = true
      ipt["10.10.10.128/25"] = true
      ipt["10.10.10.192/26"] = true

      changed = true
      while (changed) do
          changed = false
          for supernet, grp in ipt:supernets(iptable.AF_INET) do
              for subnet, _ in pairs(grp) do
                  ipt[subnet] = nil
                  changed = true
               end
               ipt[supernet] = true
          end
      end
      assert.is_equal(2, #ipt)

    end)

    it("minifies as much as possible", function()
      local ipt = iptable.new()
      assert.is_truthy(ipt)

      ipt = iptable.new()
      ipt["10.10.10.0"] = true
      ipt["10.10.10.1"] = true
      ipt["10.10.10.2"] = true
      ipt["10.10.10.3"] = true
      ipt["10.10.10.4"] = true

      changed = true
      while (changed) do
          changed = false
          for supernet, grp in ipt:supernets(iptable.AF_INET) do
              for subnet, _ in pairs(grp) do
                  ipt[subnet] = nil
                  changed = true
               end
               ipt[supernet] = true
          end
      end
      assert.is_equal(2, #ipt)

    end)

    it("will not supernets keys with 0/0", function()
      local ipt = iptable.new()
      ipt["0.0.0.0/0"] = 0
      local cnt = 0
      for k, t in ipt:supernets(iptable.AF_INET) do cnt = cnt + 1 end
      assert.is_equal(0, cnt)

      ipt["0.0.0.0/1"] = 0
      local cnt = 0
      for k, t in ipt:supernets(iptable.AF_INET) do cnt = cnt + 1 end
      assert.is_equal(0, cnt)
    end)

    it("will propose supernets to 0/0", function()
      local ipt = iptable.new()
      ipt["0.0.0.0/1"] = 1
      ipt["128.0.0.0/1"] = 2
      local cnt = 0
      local cnt = 0
      for k, t in ipt:supernets(iptable.AF_INET) do
        cnt = cnt + 1
        assert.is_equal("0.0.0.0/0", k)
        for k2, _ in pairs(t) do ipt[k2] = nil end
        ipt[k] = "default only"
      end
      assert.is_equal(1, cnt)
      assert.is_equal(1, #ipt)
    end)

    it("will propose to supernets to 0/1", function()
      local ipt = iptable.new()
      ipt["0.0.0.0/2"] = 1
      ipt["64.0.0.0/2"] = 2

      local cnt = 0
      for k, t in ipt:supernets(iptable.AF_INET) do
        cnt = cnt + 1
        assert.is_equal("0.0.0.0/1", k)
        for k2, _ in pairs(t) do ipt[k2] = nil end
        ipt[k] = "left overs"
      end
      assert.is_equal(1, cnt)
      assert.is_equal(1, #ipt)
    end)

    it("handle pairs across multiple parents", function()
      local ipt = iptable.new()
      ipt["192.168.1.0/24"] = 1

      ipt["192.168.1.0/25"] = 1
      ipt["192.168.1.128/25"] = 1

      ipt["192.168.1.0/26"] = 1
      ipt["192.168.1.64/26"] = 1

      ipt["192.168.1.128/26"] = 1
      ipt["192.168.1.192/26"] = 1

      assert.is_equal(7, #ipt)

      local done = false
      while(not done) do
        done = true
        for super, pfxs in ipt:supernets(iptable.AF_INET) do
          for pfx, _ in pairs(pfxs) do ipt[pfx] = nil end
          ipt[super] = "consolidated"
          done = false
        end
      end

      assert.is_equal(1, #ipt)
    end)

    it("handles repeated deletes", function()
      local ipt = iptable.new()
      local n
      ipt["192.168.1.0/24"] = 1
      ipt["192.168.1.0/25"] = 1

      assert.is_equal(2, #ipt)

      for n = 1, 10 do ipt["192.168.1.0/25"] = nil end
      assert.is_equal(1, #ipt)

      for n = 1, 10 do ipt["192.168.1.0/24"] = nil end
      assert.is_equal(0, #ipt)

    end)

    it("handles repeated adds", function()
      local ipt = iptable.new()
      local n

      assert.is_equal(0, #ipt)

      for n = 1, 10 do ipt["192.168.1.0/25"] = 1 end
      assert.is_equal(1, #ipt)

      for n = 1, 10 do ipt["192.168.1.0/24"] = 1 end
      assert.is_equal(2, #ipt)

    end)

  end)
end)
