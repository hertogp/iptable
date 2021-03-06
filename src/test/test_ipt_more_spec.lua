#!/usr/bin/env lua
-------------------------------------------------------------------------------
--  Description:  unit test file for iptable
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
      local sum = 0;
      local search_pfx = "1.2.3.0/24";
      for pfx, v in ipt:more(search_pfx) do
        sum = sum + v;
      end
      assert.are_equal(2+4+8+16+32+64+128, sum);
    end)

    it("finds more specifics, inclusive", function()
      local sum = 0;
      local search_pfx = "1.2.3.0/24";
      for pfx, v in ipt:more(search_pfx, true) do sum = sum + v; end
      assert.are_equal(1+2+4+8+16+32+64+128, sum);
    end)

    it("ignores more specifics that were deleted", function()
      local t = iptable.new();
      assert.is_truthy(t);

      t["10.10.10.0/24"] = 1
      t["10.10.10.0/25"] = 2
      t["10.10.10.0/26"] = 3
      t["10.10.10.0/27"] = 4  -- will be deleted in iterator-loop
      t["10.10.10.0/28"] = 5
      t["10.10.10.0/29"] = 6
      t["10.10.10.0/30"] = 7

      for k, v in pairs(t) do

        t["10.10.10.0/27"] = nil

        -- non-inclusive
        local cnt = 0;
        for p in t:more("10.10.10.0/24") do cnt = cnt + 1 end
        assert.are_equal(5, cnt);

        -- inclusive
        cnt = 0;
        for p in t:more("10.10.10.0/24", true) do cnt = cnt + 1 end
        assert.are_equal(6, cnt);
        break
      end
    end)

    it("ignores more the next more specific that was deleted", function()
      local t = iptable.new();
      assert.is_truthy(t);

      t["10.10.10.0/24"] = 1
      t["10.10.10.0/25"] = 2 -- first more specific
      t["10.10.10.0/26"] = 3 -- next in line is deleted right away
      t["10.10.10.0/27"] = 4

      -- non-inclusive
      local cnt = 0;
      for p in t:more("10.10.10.0/24") do
        t["10.10.10.0/26"] = nil
        cnt = cnt + 1
      end
      assert.are_equal(2, cnt);

    end)

    it("handles non-existing search prefixes", function()
      local sum = 0;
      local search_pfx = "10.10.10.0/24";
      for pfx, v in ipt:more(search_pfx, true) do sum = sum + v end
      assert.are_equal(0, sum);
    end)

    it("yields all entries for 0/0", function()
      local sum = 0;
      local search_pfx = "0.0.0.0/0";
      for pfx, v in ipt:more(search_pfx) do sum = sum + v; end
      assert.are_equal(1+2+4+8+16+32+64+128, sum);
    end)

    it("optionally includes 0/0 in the results", function()
      local sum = 0;
      -- add 0/0 to the table
      ipt["0.0.0.0/0"] = 256;

      -- non-inclusive will not include search term
      sum = 0;
      local search_pfx = "0.0.0.0/0";
      for pfx, v in ipt:more(search_pfx) do sum = sum + v; end
      assert.are_equal(1+2+4+8+16+32+64+128, sum);

      -- inclusive will return 0/0
      sum = 0;
      for pfx, v in ipt:more(search_pfx, true) do sum = sum + v; end
      assert.are_equal(1+2+4+8+16+32+64+128+256, sum);
    end)

    it("handles broadcast address", function()
      ipt["1.1.1.255"] = 255  -- orthogonal to 1.2.3.x/y
      cnt = 0
      for pfx, v in ipt:more("1.1.0.0/16") do cnt = cnt + v end
      assert.are.equal(255, cnt)

    end)
  end)
end)

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    ipt["1.1.255.255"] = 1
    ipt["2.1.255.255"] = 2
    ipt["3.1.255.255"] = 4

    it("finds more specifics, non-inclusive", function()
      local sum = 0;
      local search_pfx = "1.0.0.0/8";
      for pfx, v in ipt:more(search_pfx) do
        sum = sum + v;
      end
      assert.are_equal(1, sum);
    end)
  end)
end)

describe("ipt:more(pfx): ", function()

  expose("instance ipt: ", function()
    iptable = require("iptable");
    assert.is_truthy(iptable);
    ipt = iptable.new();
    assert.is_truthy(ipt);

    ipt["1.1.255.255"] = 1
    ipt["3.1.255.255"] = 4

    it("finds more specifics, non-inclusive", function()
      local sum = 0;
      local search_pfx = "1.1.0.0/16";
      for pfx, v in ipt:more(search_pfx) do sum = sum + v; end
      assert.are_equal(1, sum);
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
        for pfx in t:more("0.0.0.0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more("255.255.255.255", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more("0.0.0.0/0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more("255.255.255.255/0", incl) do cnt = cnt + 1; end
        assert.are_equal(#t, cnt);
      end

      -- (non-)inclusive search finds nothing in an empty table
      for _,incl in ipairs{false, true} do
        local cnt = 0;
        for pfx in t:more("1.1.1.1/0", incl) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
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
          for p in t:more(pfx) do cnt = cnt + 1; end
          assert.are_equal(0, cnt);

          -- inclusive
          cnt = 0;
          for p in t:more(pfx, true) do cnt = cnt + 1; end
          assert.are_equal(1, cnt);

        end -- for mask
      end -- for stem
    end)


  end)
end)
