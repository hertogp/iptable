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

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    ipt["1.2.3.0/24"] = 1
    ipt["1.2.3.0/25"] = 1
    ipt["1.2.3.0/26"] = 2
    ipt["1.2.3.192/27"] = 1
    ipt["1.2.3.0/27"] = 2

    ipt["1.2.5.128/25"] = 4
    ipt["1.2.5.128/26"] = 4

    local fh = io.open("tmp/tmp/00.dot", "w")
    fh:write(table.concat(dotify(ipt, "00", iptable.AF_INET)), "\n")
    fh:close()

    it("finds prefixes that are able to merge", function()
      local cnt = 0
      for p, t in ipt:merge(iptable.AF_INET) do
        cnt = cnt + 1
        print(F("%s may replace:", p), t)
        if not t[p] then t[p] = 42 end
        for k,v in pairs(t) do
          -- if k ~= p then ipt[k] = nil end
          print(F("%20s - %s (deleted)", k,v))
        end
        local fh = io.open(F("tmp/tmp/%02d.dot", cnt), "w")
        fh:write(table.concat(dotify(ipt, F("%02d", cnt), iptable.AF_INET)), "\n")
        fh:close()

      end
    end)
  end)
end)
