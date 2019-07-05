#!/usr/bin/env lua

package.cpath = "./build/?.so;"

F = string.format

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
      for p in ipt:less("1.1.1.192/26") do
        t[#t+1] = p
        print(p)
      end
      assert.are.equal(2, #t)
      assert.is_true(t["1.1.1.128/25"])
      assert.is_true(t["1.1.1.0/24"])

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

