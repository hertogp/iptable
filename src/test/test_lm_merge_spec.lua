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
package.path = "./src/lua/?.lua"

local dotify = require("ipt2smalldot")

-- helpers

F = string.format

-- tests
local function mergecb(pfx, t)
  -- pfx is the pfx to replace all that is in table t, {pfx->value}
  -- pfx may or may not be in table t.
  -- return a table with keepers.
  print(F("%20s, may replace:", pfx))
  for p, v in pairs(t) do
    print(F(" - %20s - %s", p, v))
  end
  -- return table with pfx's to be preserved
  return { [pfx] = #t }
end

describe("ipt:merge(): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);


    it("finds prefixes that are able to merge", function()
      local cnt = 0
      local ipt = iptable.new();
      assert.is_truthy(ipt);

      ipt["1.2.3.0/24"] = 1     -- sole supernet entry
      ipt["1.2.3.0/25"] = 2     -- paired w/ the next entry
      ipt["1.2.3.128/25"] = 4
      ipt["1.2.3.0/26"] = 8     -- paired w/ the next entry
      ipt["1.2.3.64/26"] = 16
      ipt["1.2.3.128/26"] = 32  -- paired w/ the next entry
      ipt["1.2.3.192/26"] = 64

      for p, t in ipt:merge(iptable.AF_INET) do
        cnt = cnt + 1
        io.write(F("%s <-->", p))
        for k,v in pairs(t) do io.write(F(" %s (%s)", k, v)) end
        io.write("\n")
        -- if cnt > 5 then break end
      end
    end)

    it("is safe to delete both the super and paired-keys", function()
      local ipt = iptable.new();
      assert.is_truthy(ipt);

      ipt["1.2.3.0/24"] = 1     -- sole supernet entry
      ipt["1.2.3.0/25"] = 2     -- paired w/ the next entry
      ipt["1.2.3.128/25"] = 4
      ipt["1.2.3.0/26"] = 8     -- paired w/ the next entry
      ipt["1.2.3.64/26"] = 16
      ipt["1.2.3.128/26"] = 32  -- paired w/ the next entry
      ipt["1.2.3.192/26"] = 64
      local checksum = 0 -- calculate the sum of all values
      for k,v in pairs(ipt) do checksum = checksum + v end

      -- rearrange the tree 
      for p, t in ipt:merge(iptable.AF_INET) do
        local sum = 0
        for k, v in pairs(t) do
          ipt[k] = nil   -- delete the subnets (and possibly supernet if any)
          sum = sum + v  -- sum their values
        end
        -- supernet prefix is created anew with the sum of the values
        ipt[p] = sum     -- set supernet value to the calculated sum
      end
      -- recalculate the total sum, it should be the same
      local sum = 0
      for k,v in pairs(ipt) do sum = sum + v end
      assert.is_equal(checksum, sum)
      assert.is_equal(3, #ipt)
    end)

    it("will not merge keys with 0/0", function()
      local ipt = iptable.new()
      ipt["0.0.0.0/0"] = 0
      local cnt = 0
      for k, t in ipt:merge(iptable.AF_INET) do cnt = cnt + 1 end
      assert.is_equal(0, cnt)

      ipt["0.0.0.0/1"] = 0
      local cnt = 0
      for k, t in ipt:merge(iptable.AF_INET) do cnt = cnt + 1 end
      assert.is_equal(0, cnt)
    end)

    -- it("will not propose to merge to 0/0", function()
    --   print("--1--")
    --   local ipt = iptable.new()
    --   ipt["0.0.0.0/1"] = 1
    --   ipt["128.0.0.0/1"] = 2
    --   local cnt = 0
    --   for k,v in pairs(ipt) do print(k,v) end
    --   local cnt = 0
    --   for k, t in ipt:merge(iptable.AF_INET) do
    --     cnt = cnt + 1
    --     assert.is_equal("0.0.0.0/0", k)
    --   end
    --   assert.is_equal(1, cnt)
    -- end)

    it("will propose to merge to 0/1", function()
      print("--2--")
      local ipt = iptable.new()
      ipt["0.0.0.0/2"] = 1
      ipt["64.0.0.0/2"] = 2
      print(iptable.network("128.0.0.0/2"))
      print(iptable.network("128.0.0.0/1"))
      print(iptable.broadcast("0.0.0.0/2"))

      local fh = io.open("tmp/tmp/00.dot", "w")
      fh:write(table.concat(dotify(ipt, "00", iptable.AF_INET)), "\n")
      fh:close()

      local cnt = 0
      for k,v in pairs(ipt) do print(k,v) end
      for k, t in ipt:merge(iptable.AF_INET) do
        cnt = cnt + 1
        assert.is_equal("0.0.0.0/1", k)
      end
      assert.is_equal(1, cnt)
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


      local cnt = 0
      print("-----")
      for k,v in pairs(ipt) do print(k,v) end
      for k, t in ipt:merge(iptable.AF_INET) do
        io.write(F("%s <--> ", k))
        for s, _ in pairs(t) do
          io.write(F(" %s", s))
        end
        io.write("\n")
        cnt = cnt + 1
      end
      assert.is_equal(1, cnt)
    end)


  end)
end)
