#!/usr/bin/env lua

package.cpath = "./build/?.so;"

local F = string.format
local iptable = require("iptable");

describe("iptable pairs(t) iteration: ",
function()

  it("yields no results for an empty table",
  function()
    local t = iptable.new()
    local n = 0
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(0, n)
  end)

  it("yields 1 result for a table with a 0.0.0.0 host entry ",
  function()
    local t = iptable.new()
    local n = 0
    t["0.0.0.0"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(1, n)
  end)

  it("yields 1 result for a table with a 0.0.0.0/0 default entry ",
  function()
    local t = iptable.new()
    local n = 0
    t["0.0.0.0/0"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(1, n)
  end)

  it("yields 1 result for a table with a 255.255.255.255/0 default entry ",
  function()
    local t = iptable.new()
    local n = 0
    t["255.255.255.255/0"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(1, n)
  end)

  it("yields 1 result for a table with a 255.255.255.255 host entry ",
  function()
    local t = iptable.new()
    local n = 0
    t["255.255.255.255"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(1, n)
  end)

  it("yields 1 result for an explicit default entry (/0)",
  function()
    local t = iptable.new()
    local n = 0
    t["0.0.0.0/0"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(1, n)
  end)

  it("yields 2 results for a table with a 0 & 255.255.255.255 host entries ",
    function()
      local t = iptable.new()
      local n = 0
      t["0.0.0.0"] = 1
      t["255.255.255.255"] = 1
      for k,v in pairs(t) do n = n + 1 end
      assert.is.equal(2, n)
    end)


  it("yields 2 result for an normal + explicit default entry",
  function()
    local t = iptable.new()
    local n = 0
    t["0.0.0.0/0"] = 1
    t["0.0.0.1"] = 1
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(2, n)
  end)

  it("yields all entries for host addresses",
  function()
    local t = iptable.new()
    local n = 0
    for i=0, 255 do t[F("1.1.1.%d",i)] = i end
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(256, n)
  end)

  it("yields all entries for a bunch of networks",
  function()
    local t = iptable.new()
    local n = 0
    for i=1, 255 do t[F("1.1.%d.0/24",i)] = i end
    for k,v in pairs(t) do n = n + 1 end
    assert.is.equal(255, n)

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

