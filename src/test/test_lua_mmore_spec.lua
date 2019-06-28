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

-- helpers

F = string.format

-- tests

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    ipt["1.2.3.0/24"] = 1
    ipt["1.2.3.0/25"] = 2
    ipt["1.2.3.128/25"] = 4
    ipt["1.2.3.128/26"] = 8
    ipt["1.2.3.192/26"] = 16
    ipt["1.2.3.128/27"] = 32
    ipt["1.2.3.128/28"] = 64
    ipt["1.2.3.144/28"] = 128

    it("finds more specifics, non-inclusive", function()
      local cnt = 0;
      local search_pfx = "1.2.3.0/24";
      for pfx in ipt:more2(search_pfx) do
        cnt = cnt + 1;
      end
      assert.are_equal(7, cnt);
    end)

    it("finds more specifics, inclusive", function()
      local cnt = 0;
      local search_pfx = "1.2.3.0/24";
      for pfx in ipt:more2(search_pfx, true) do
        cnt = cnt + 1;
      end
      assert.are_equal(8, cnt);
    end)

    it("handles non-existing search prefixes", function()
      local cnt = 0;
      local search_pfx = "10.10.10.0/24";
      for pfx in ipt:more2(search_pfx, true) do
        cnt = cnt + 1;
      end
      assert.are_equal(0, cnt);
    end)

    it("yields all entries for 0/0", function()
      local cnt = 0;
      for pfx in ipt:more2("10.10.10.0/0") do
        cnt = cnt + 1;
      end
      assert.are_equal(8, cnt);
    end)

    it("optionally includes 0/0 in the results", function()
      local cnt = 0;

      -- add 0/0 to the table
      ipt["0.0.0.0/0"] = 256;

      -- non-inclusive does not return 0/0
      for pfx in ipt:more2("10.10.10.0/0") do
        cnt = cnt + 1;
      end
      assert.are_equal(8, cnt);

      -- inclusive will return 0/0
      cnt = 0;
      for pfx in ipt:more2("10.10.10.0/0", true) do
        cnt = cnt + 1;
      end
      assert.are_equal(9, cnt);


    end)

  end)
end)

describe("ipt:more(pfx) ", function()

  expose("instance: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    it("gets array of more specific prefixes", function()
      local cnt = 0
      ipt["1.1.1.0/24"] = 24;
      ipt["1.1.1.0/25"] = 25;
      ipt["1.1.1.128/25"] = 25;
      ipt["1.1.1.0/26"] = 26;
      ipt["1.1.1.64/26"] = 26;
      ipt["1.1.1.128/26"] = 26;
      ipt["1.1.1.192/26"] = 26;
      assert.is_truthy(7 == #ipt);

      -- non-inclusive
      cnt = 0
      for p in ipt:more2("1.1.1.0/24") do cnt = cnt + 1 end
      assert.are.equal(6, cnt);

      -- inclusive
      cnt = 0
      for p in ipt:more2("1.1.1.0/24", true) do cnt = cnt + 1 end
      assert.are.equal(7, cnt);

      -- should find two /26's
      cnt = 0
      for p in ipt:more2("1.1.1.0/25") do cnt = cnt + 1 end
      assert.are.equal(2, cnt);

      -- inclusive search
      cnt = 0
      for p in ipt:more2("1.1.1.0/25", true) do cnt = cnt + 1 end
      assert.are.equal(3, cnt);

      -- nothing more specific for 1.1.1.0/26
      cnt = 0
      for p in ipt:more2("1.1.1.0/26") do cnt = cnt + 1 end
      assert.are.equal(0, cnt);

      -- inclusive search
      cnt = 0
      for p in ipt:more2("1.1.1.0/26", true) do cnt = cnt + 1 end
      assert.are.equal(1, cnt);
    end)

    it("will find results if search prefix itself is absent", function()
      local cnt;
      local ipt = iptable.new()
      ipt["1.1.1.128/25"] = 25;
      ipt["1.1.1.64/26"] = 26;
      ipt["1.1.1.128/26"] = 26;
      ipt["1.1.1.192/26"] = 26;
      assert.is_truthy(4 == #ipt);

      -- 1.1.1.0/24 is not in table, but more specific entries exist
      cnt = 0
      for p in ipt:more2("1.1.1.0/24") do cnt = cnt + 1 end
      assert.are.equal(4, cnt);

      cnt = 0
      for p in ipt:more2("1.1.1.0/24", true) do cnt = cnt + 1 end
      assert.are.equal(4, cnt);
    end)

  end)
end)

describe("ipt:more(pfx): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("finds nothing in empty table", function()
      local t = iptable.new();
      assert.is_truthy(t);

      -- 0.0.0.0 and 255.255.255.255 are always in the radix tree as root nodes
      -- but should never match unless they were added explicitly to the tree

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more2("0.0.0.0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more2("255.255.255.255", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more2("0.0.0.0/0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more2("255.255.255.255/0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more2("1.1.1.1/0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

    end)
  end)
end)

describe("ipt:more(pfx): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("handles a single entry {0..255}.0.0.0/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("0.0.0.%d/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)


    it("handles a single entry 0.{0..255}.0.0/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("0.%d.0.0/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)


    it("handles a single entry 0.0.{0..255}.0/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("0.0.%d.0/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)


    it("handles a single entry 0.0.0.{0..255}/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("0.0.0.%d/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)
  end)
end)


describe("ipt:more(pfx): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("handles a single entry 255.255.{0..255}.255/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("255.255.%d.255/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

    it("handles a single entry 255.{0..255}.255.255/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("255.%d.255.255/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

    it("handles a single entry {0..255}.255.255.255/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("%d.255.255.255/%d", stem, mask)  -- pfx = 0/0 .. 255/32
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

    it("handles a single entry 255.255.255.{0..255}/{0..32}", function()

      for stem=0,255 do
        for mask=0,32 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("255.255.255.%d/%d", stem, mask)
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

  end)
end)

describe("ipt:more(pfx6): ", function()

  expose("ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);

    it("handles a single entry xx::/{0..128}", function()

      for stem=0,255 do
        for mask=0,128 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("%02x::/%d", stem, mask)
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

    it("handles a single entry 00:xx::/{0..128}", function()

      for stem=0,255 do
        for mask=0,128 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("00:%02x::/%d", stem, mask)
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

    it("handles a single entry 00::xx/{0..128}", function()

      for stem=0,255 do
        for mask=0,128 do

          local t = iptable.new();
          assert.is_truthy(t);

          local pfx = F("::%02x/%d", stem, mask)
          t[pfx] = 1

          -- non-inclusive
          local cnt = 0;
          for p in t:more2(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more2(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)

  end)
end)
