--
------------------------------------------------------------------------------
--         File:  ipt2dot.lua
--
--        Usage:  require("ipt2dot")(ipt, iptable.AF_<fam>) -> {lines, edges}
--
--  Description:  convert iptable radix tree to graphviz code
--
--      Options:  ---
-- Requirements:  ---
--         Bugs:  ---
--        Notes:  ---
--       Author:  YOUR NAME (), <>
-- Organization:  
--      Version:  1.0
--      Created:  22-06-19
--     Revision:  ---
------------------------------------------------------------------------------
--

local F = assert(string.format)

local function panic(t)
  -- dump a table for which there is no handler and exit
  print("panic! -- table %s is unknown and has no handler")
  for k,v in pairs(t) do
    print(" k,v = ", k, v)
  end
  os.exit(1)
end

local function escape(s)
  local escapees = {
    [ "\r" ] = "\\r",
    [ "\n" ] = "\\n",
    [ "\t" ] = "\\t",
    [ "\f" ] = "\\f",
    [ "\v" ] = "\\v",
    [ "\\" ] = "\\\\",
    [ "'" ] = "\\'",
    [ "<" ] = "&lt;",
    [ ">" ] = "&gt;",
    [ "&" ] = "&amp;",
    [ '"' ] = "&quot;",
  }
  local function escaper(c)
    return F("\\%03d", string.byte(c))
  end

  s = string.gsub(s, "[\r\n\t\f\v\\'<>&\"]", escapees )
  s = string.gsub(s, "[^][%w !\"#$%%&'()*+,./:;<=>?@\\^_`{|}~-]", escaper )
  return s
end


--[[ format strings for pieces of an HTML table ]]

-- TBL_LABEL params: node_id, html-table (as string)
-- Wraps an HTML-table in a label for a given (unique) node
local TBL_LABEL = [[
%s [label=<%s>,shape="plaintext"];
]]

-- TBL_START: no params
-- Start of the table
local TBL_START = [[
  <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
]];

-- TBL_HEAD params: PORT=head_id, bgcolor, title
-- A title of the (sub)table
local TBL_HEAD = [[
    <TR><TD%s COLSPAN="2" BGCOLOR="%s">%s</TD></TR>
]];

-- TBL_KEYVAL params: key, PORT=value_id, value
-- A key, value pair; PORT="some_ID" in case value is a pointer to some node
local TBL_KEYVAL = [[
    <TR><TD>%s</TD><TD%s>%s</TD></TR>
]];
-- TBL_END: no params
-- Ends the table definition
local TBL_END = [[
  </TABLE>
]]

-- background color for table (sub)headers
local function th_bgcolor(node)
  bgcolors = {
    nill = "white",
    RADIX_NODE_HEAD = "yellow",
    RADIX_HEAD = "khaki",
    RADIX_NODE_ROOT = "yellow",         -- flags are not mutually exclusive
    RADIX_NODE_LEAF = "green",          -- favor ROOT over LEAF/INTERNAL
    RADIX_NODE_INTERNAL = "lightgrey",
    RADIX_MASK_HEAD = "gold",
    RADIX_MASK = "coral",
    default = "khaki",
  }

  if (node == nil) then return bgcolors.nill end
  -- try color by node name
  local bgcolor = bgcolors[node._NAME_]
  if (bgcolor) then return bgcolor end
  -- try color by radix_node 'kind'
  if (node._ROOT_) then return bgcolors.RADIX_NODE_ROOT end
  if (node._LEAF_) then return bgcolors.RADIX_NODE_LEAF end
  if (node._INTERNAL_) then return bgcolors.RADIX_NODE_INTERNAL end
  -- fallback to default
  return bgcolors.default
end

local function t_node_id(t)
  if (type(t) == "table") then
    return F("N%s", t._MEM_)
  else
    panic(t)
  end
end

local function t_flags(t)
  if (type(t) ~= "table") then return nil end
  local tag = ""
  tag = t._ROOT_ and "R" or ""
  tag = t._NORMAL_ and tag.."N" or tag
  tag = t._ACTIVE_ and tag.."A" or tag
  return tag
end
local function t_tag(t)
  if (type(t) ~= "table") then return nil end
  if t._LEAF_ then return "L" end
  if t._INTERNAL_ then return "I" end
  return "?"
end


local function trowkv(g, k, v)
  -- add a key,val row to some (sub)table with 'node_id'
  -- by convention: if v is 0x<hex> it's a pointer to some node elsewhere
  local arrowstyle = {
    rn_left     = '[style="solid",  color="blue"]',
    rn_right    = '[style="dashed",  color="blue"]',
    rn_dupedkey = '[style="dotted", color="blue"]',
    rn_mklist   = '[style="dashed", color="coral"]',
    rn_parent   = '[style="dashed"]',
    rm_leaf     = '[style="dashed", color="coral"]',
  }
  local port_id, tgt_node_id = "", ""
  local PORT = ""


  if (g == nil or k == nil or v == nil) then -- panic!
    print("[ERROR][FATAL] trowkv: received nil(s) as args: g,k,v", g,k,v)
    os.exit(1)
    panic({
      error = "fatal",
      trowkv = F("received 1 or more nil args: %s,%s,%s", g,k,v)
  })
  end

  v = tostring(v)
  if (v:match("^0x[0-9a-fA-F]+$")) then
    -- for non-NULL pointers, add PORT & edge
    local style = arrowstyle[k] or '[style="solid", color="black"]'
    tgt_node_id = F("N%s", v) -- (sub)table PORT is N<address>
    port_id = F("%s_%s", g.node_id, #g.lines) -- ensure a unique port_id
    g.ports[port_id] = g.node_id -- this unique port_id belongs to  node_id
    g.edges[#g.edges+1] = {g.node_id, port_id, tgt_node_id, style}
    PORT = F(" PORT=\"%s\"", port_id)
  end

  g.lines[#g.lines+1] = F(TBL_KEYVAL, escape(k), PORT, escape(v))
end


local function theader(g, t)
  -- add a single column row as header for (sub)table t's subsequent rows
  -- Note: (sub)tables have an incoming PORT
  local port_id = F("N%s", t._MEM_) -- (sub)table PORT is N<address>
  local PORT = F(" PORT=\"%s\"", port_id)
  local title = F("%s - %s", t._NAME_, t._MEM_)
  g.lines[#g.lines+1] = F(TBL_HEAD, PORT, th_bgcolor(t), escape(title))
  -- register as an incoming port for this node
  g.ports[port_id] = g.node_id
end


local function rn_dot_body(g, t)
  -- radix_node's body lines
  -- separated out since other structs contain radix_nodes as well
  --  in which case we donot want it wrapped in its own table

  trowkv(g, "rn_mklist", t.rn_mklist)
  trowkv(g, "rn_parent", t.rn_parent)
  trowkv(g, "rn_bit", F("%s (%s)", t.rn_bit, t_tag(t)))
  trowkv(g, "rn_bmask", F("%02x", 0xFF & t.rn_bmask))
  trowkv(g, "rn_flags", F("%s (%s)", t.rn_flags, t_flags(t)))

  if (t._LEAF_) then
    trowkv(g, "rn_key", t.rn_key)
    trowkv(g, "rn_mask", t.rn_mask)
    trowkv(g, "rn_dupedkey", t.rn_dupedkey)
  else
    trowkv(g, "rn_offset", t.rn_offset)
    trowkv(g, "rn_left", t.rn_left)
    trowkv(g, "rn_right", t.rn_right)
  end
end

local function rn_dot(g, t)
  g.lines = {}
  g.node_id = t_node_id(t)

  theader(g, t)
  rn_dot_body(g, t)

  local tbl = TBL_START..table.concat(g.lines)..TBL_END
--  g.nodes[#g.nodes+1] = F(TBL_LABEL, g.node_id, tbl)
  return F(TBL_LABEL, g.node_id, tbl)
end

local function rnh_dot(g, t)
  -- output a dot html table & register this node's edges
  g.lines = {}
  g.node_id = t_node_id(t)

  -- RADIX_NODE_HEAD
  theader(g, t)

  -- RADIX_HEAD part
  theader(g, t.rh)
  trowkv(g, "rnh_treetop", t.rh.rnh_treetop)
  trowkv(g, "rnh_masks", t.rh.rnh_masks)

  -- RADIX_NODES part
  theader(g, t)
  for idx, rn in ipairs(t.rnh_nodes) do
    theader(g, rn)
    rn_dot_body(g, rn)
  end

  -- create the node as string
  local tbl = TBL_START..table.concat(g.lines)..TBL_END
--  g.nodes[#g.nodes+1] = F(TBL_LABEL, g.node_id, tbl)
  return F(TBL_LABEL, g.node_id, tbl)
end

local function rmh_dot(g, t)
  -- output a dot html table & register this node's edges
  g.lines = {}
  g.node_id = t_node_id(t)

  -- RADIX_NODE_HEAD
  theader(g, t)

  -- RADIX_HEAD part
  theader(g, t.head)
  trowkv(g, "rnh_treetop", t.head.rnh_treetop)
  trowkv(g, "rnh_treetop", t.head.rnh_masks)

  -- RADIX_NODES part
  theader(g, t.mask_nodes)
  for idx, rn in ipairs(t.mask_nodes) do
    theader(g, rn)
    rn_dot_body(g, rn)
  end

  -- create the node
  local tbl = TBL_START..table.concat(g.lines)..TBL_END
-- g.nodes[#g.nodes+1] = F(TBL_LABEL, g.node_id, tbl)
  return F(TBL_LABEL, g.node_id, tbl)
end

local function rm_dot(g, t)
  g.lines = {}
  g.node_id = t_node_id(t)

  theader(g, t)
  trowkv(g, "rm_bit", t.rm_bit)
  trowkv(g, "rm_unused", t.rm_unused)
  trowkv(g, "rm_flags", F("%s (%s)", t.rm_flags, t_flags(t)))
  trowkv(g, "rm_mklist", t.rm_mklist)

  if (t._LEAF_) then
    trowkv(g, "rm_leaf", t.rm_leaf)
  else
    trowkv(g, "rm_mask", t.rm_mask)
  end
  trowkv(g, "rm_refs", t.rm_refs)

  local tbl = TBL_START..table.concat(g.lines)..TBL_END
--  g.nodes[#g.nodes+1] = F(TBL_LABEL, g.node_id, tbl)
  return F(TBL_LABEL, g.node_id, tbl)
end

local function tbl2dot(g, t)
  local hdlrs = {
    RADIX_NODE_HEAD = rnh_dot,
    RADIX_NODE = rn_dot,
    RADIX_MASK_HEAD = rmh_dot,
    RADIX_MASK = rm_dot,
  }

  local hdlr = hdlrs[t._NAME_]

  if (hdlr) then
    return hdlr(g, t)
  else
    panic(t)
  end
end



local M = {}

function dotify(ipt, af_fam)
  local lines = {}
  local graph = {         -- collector for graph info
    lines = {},     -- transient storage for lines of the current node
--    nodes = {},     -- array of nodes in the graph
    edges = {},     -- register for (incomplete) edges (across the graph)
    ports = {}      -- map (unique) port_id->node_id (across the graph)
  }

  -- start the graph
  lines[#lines+1] = "digraph G {";
  lines[#lines+1] = "  rankdir=\"LR\";";
  lines[#lines+1] = "  ranksep=\"1.0 equally\";\n";

  -- collect all RADIX node types
  for radix in ipt:radixes(af_fam) do
    lines[#lines+1] = tbl2dot(graph, radix)
  end

  for _, edge in ipairs(graph.edges) do
    local snode, sport, dport, style = table.unpack(edge)
    local dnode = graph.ports[dport]
    style = style or ""
    if (dnode) then
      if (snode ~= dnode) then
        lines[#lines+1] = F("%s:%s -> %s:%s %s",
                            snode, sport, dnode, dport, style)
      else
        --lines[#lines+1] = F("%s:%s -> %s:%s [style=%s]",
        --                    snode, sport, dnode, dport, style))
      end
    else
      lines[#lines+1] = F("%s:%s -> %s", snode, sport, dport)
    end
  end

  lines[#lines+1] = "}";

  return lines
end

return dotify

--[[ example usage ]]

-- iptable = require("iptable")
-- dotify = require("ipt2dot")

-- local iptable = require("iptable")
-- local ipt = iptable.new()
-- ipt["1.1.1.0/24"] = 24

-- ipt["1.1.1.0/25"] = 25
-- ipt["1.1.1.128/25"] = 25

-- ipt["1.1.1.0/26"] = 25
-- ipt["1.1.1.64/26"] = 25
-- ipt["1.1.1.128/26"] = 25
-- ipt["1.1.1.192/26"] = 25

-- ipt["3.1.1.0/24"] = 24
-- ipt["3.1.1.0/25"] = 24
-- ipt["3.1.1.128/25"] = 24

-- local mylines = dotify(ipt, iptable.AF_INET)
-- print(table.concat(mylines, "\n"))
