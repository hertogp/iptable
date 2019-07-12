--
------------------------------------------------------------------------------
--     File:  ipt2small.lua
--
--     Usage:  require("ipt2smalldot")(ipt, iptable.AF_<fam>)->{lines, edges}
--
--  Description:  convert iptable radix tree to minimalistic graphviz code
--
------------------------------------------------------------------------------

local F = assert(string.format)

local function node(x)
  -- ensures graphviz likes the node id's
  if type(x) == "table" then
    return "n"..x._MEM_
  elseif type(x) == "string" then
    if x == "(nil)" then return nil end
    return "n"..x
  else
    return x
  end
end

local function t_flags(t)
  -- string radix node flags together
  if (type(t) ~= "table") then return nil end
  local tag = t._ROOT_ and "R" or ""
  tag = t._NORMAL_ and tag.."N" or tag
  tag = t._ACTIVE_ and tag.."A" or tag
  return tag
end

local function t_type(t)
  -- type of node: leaf, internal or unknown?
  if (type(t) ~= "table") then return nil end
  if t._LEAF_ then return "L" end
  if t._INTERNAL_ then return "I" end
  return "?"
end


local function rn_dot(g, t)
  local RN = node(t)
  local fmt_leaf = "[shape=plaintext,label=\"%s/%s\n(%s) %s\"];"
  local fmt_internal = "[shape=plaintext,label=\"(%s) %s\"];"
  -- skip radix_masks for now
  -- g.edges[#g.edges+1] = {RN, node(t.rn_mklist)}

  if t._LEAF_ then
    g.nodes[RN] = F(fmt_leaf,  t.rn_key, t._rn_mlen, t.rn_bit, t_flags(t))
    g.edges[#g.edges+1] = {RN, node(t.rn_dupedkey), "d"}

  else
    local RN_left = node(t.rn_left)
    local RN_right = node(t.rn_right)

    g.nodes[RN] = F(fmt_internal, t.rn_bit, t_flags(t))
    g.edges[#g.edges+1] = {RN, RN_left, "L"}
    g.edges[#g.edges+1] = {RN, RN_right, "R"}
    -- left -> right, used in invis rank to keep left to the left of right
    g.edges[#g.edges+1] = {RN_left, RN_right, "I"}
  end

end

local function rnh_dot(g, t)
  local RN
  -- RADIX_NODES part
  -- LE marker
  rn_dot(g, t.rnh_nodes[1])
  RN = node(t.rnh_nodes[1])
  g.nodes[RN] = F("[label=\"LE (%s)\"];", t.rnh_nodes[1].rn_bit)

  -- TT marker
  rn_dot(g, t.rnh_nodes[2])
  RN = node(t.rnh_nodes[2])
  g.nodes[RN] = F("[label=\"TT (%s)\"];", t.rnh_nodes[2].rn_bit)

  -- RE marker
  RN = node(t.rnh_nodes[3])
  rn_dot(g, t.rnh_nodes[3])
  g.nodes[RN] = F("[label=\"RE (%s)\"]", t.rnh_nodes[3].rn_bit)

end

local hdlrs = {
  RADIX_NODE_HEAD = rnh_dot,
  RADIX_NODE = rn_dot,
}
local function tbl2dot(g, t)
  local hdlr = hdlrs[t._NAME_]
  if (hdlr) then hdlr(g, t) end
end

local M = {} -- the module

function dotify(ipt, title, ...)
  local lines = {}
  local graph = {   -- collector for graph info
    nodes = {},
    edges = {},
  }

  -- start the graph
  lines[#lines+1] = "digraph G {"
  -- lines[#lines+1] = F("  size=%q;", "7.5,7.5")
  lines[#lines+1] = F("  label=%q;", title or "")
  lines[#lines+1] = "  splines=line;"
  lines[#lines+1] = F("  ranksep=%q;", "1.0 equally")

  -- collect all RADIX node types of AF_families given (...)
  for radix in ipt:radixes(...) do
    -- skip the radix tree stuff
    if radix._NAME_ == "RADIX_MASK_HEAD" then break end
    tbl2dot(graph, radix)
  end

  -- nodes
  lines[#lines+1] = "\n  /* nodes */\n"
  local fmt_node = "   %s %s"
  for k, v in pairs(graph.nodes) do
    if (k) then lines[#lines+1] = F(fmt_node, k, v); end
  end

  -- edges
  lines[#lines+1] = "\n  /* edges */\n"
  local fmt_edge = "  %s -> %s [label=\" %s\",style=%s];"
  for k, v in ipairs(graph.edges) do
    local src, dst, lbl = table.unpack(v)
    if (src and dst) then
      if lbl ~= "I" then
        local line_style = lbl=="d" and "dotted" or "solid"
        lines[#lines+1] = F(fmt_edge, src, dst, lbl, line_style);
      end
    end
  end

  -- add invisible ranks to keep left to the left of right
  lines[#lines+1] = "\n  /* keep left to the left of right */\n"
  local fmt_l2r = "  { rank=same; rankdir=LR; %s -> %s [style=invis]; }"
  for k, v in ipairs(graph.edges) do
    local src, dst, lbl = table.unpack(v)
    if (src and dst) then
      if lbl == "I" then
        lines[#lines+1] = F(fmt_l2r, src, dst, lbl)
      end
    end
  end

  lines[#lines+1] = "\n}"

  return lines
end

return dotify

--[[ example usage

iptable = require("iptable")
dotify = require("ipt2dot")

local iptable = require("iptable")
local ipt = iptable.new()
ipt["1.1.1.0/24"] = 24

ipt["1.1.1.0/25"] = 25
ipt["1.1.1.128/25"] = 25

ipt["1.1.1.0/26"] = 25
ipt["1.1.1.64/26"] = 25
ipt["1.1.1.128/26"] = 25
ipt["1.1.1.192/26"] = 25

ipt["3.1.1.0/24"] = 24
ipt["3.1.1.0/25"] = 24
ipt["3.1.1.128/25"] = 24

local mylines = dotify(ipt, iptable.AF_INET)
print(table.concat(mylines, "\n"))

]]
