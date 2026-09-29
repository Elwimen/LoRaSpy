-- LoRaSpy Wireshark dissectors
--
--   meshtastic  LoRa sync word 0x2B (registered in the loratap.syncword table)
--   meshcore    LoRa sync word 0x12
--   sdrmon      post-dissector: what LoRaSpy decoded/decrypted (from the packet comment
--               "sdrmon1 key=value ..."), for every frame including LoRaWAN
--
-- Meshtastic payloads are decoded with Wireshark's protobuf dissector; point its search
-- paths at the Meshtastic .proto files (tools/wireshark/install.sh does that).

local f_comment = Field.new("frame.comment")

local function unquote(s)
  return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

-- parse the sdrmon1 comment into a table (nil if the frame has none)
local function sdrmon_kv()
  local comments = { f_comment() }
  for _, c in ipairs(comments) do
    local s = tostring(c.value)
    if s:sub(1, 8) == "sdrmon1 " then
      local kv = {}
      for k, v in s:sub(9):gmatch("([%w_]+)=(%S*)") do kv[k] = unquote(v) end
      return kv
    end
  end
  return nil
end

local function hex_tvb(hex, name)
  if not hex or hex == "" then return nil end
  return ByteArray.new(hex):tvb(name)
end

-- minimal protobuf reader for meshtastic.Data: field 1 portnum (varint), 2 payload (bytes)
local function read_varint(tvb, off)
  local v, shift = 0, 0
  while off < tvb:len() do
    local b = tvb(off, 1):uint()
    v = v + (b & 0x7F) * (1 << shift)
    off = off + 1
    if b < 0x80 then return v, off end
    shift = shift + 7
  end
  return nil, off
end

local function data_fields(tvb)
  local off, portnum, poff, plen = 0, nil, nil, nil
  while off < tvb:len() do
    local key; key, off = read_varint(tvb, off)
    if not key then break end
    local fnum, wt = key >> 3, key & 7
    if wt == 0 then
      local v; v, off = read_varint(tvb, off)
      if fnum == 1 then portnum = v end
    elseif wt == 2 then
      local l; l, off = read_varint(tvb, off)
      if fnum == 2 then poff, plen = off, l end
      off = off + l
    elseif wt == 5 then off = off + 4
    elseif wt == 1 then off = off + 8
    else break end
  end
  return portnum, poff, plen
end

-- LoRaTap sets the gateway EUI as source address, and Wireshark fills the Source column
-- from addresses after dissection (overwriting our text). Lua can't build a text address,
-- so blank the source addresses with the (empty) destination ones, then set column text.
local function set_endpoints(pinfo, src, dst)
  pinfo.dl_src = pinfo.dl_dst
  pinfo.net_src = pinfo.net_dst
  pinfo.src = pinfo.dst
  pinfo.cols.src = src
  pinfo.cols.dst = dst
end

local protobuf = Dissector.get("protobuf")
local function pb(tvb, pinfo, tree, msgtype)
  if not protobuf or not tvb then return end
  pinfo.private["pb_msg_type"] = "message," .. msgtype
  pcall(function() protobuf:call(tvb, pinfo, tree) end)
end

---------------------------------------------------------------------- Meshtastic

local PORTNUMS = {
  [0] = "UNKNOWN_APP", [1] = "TEXT_MESSAGE_APP", [2] = "REMOTE_HARDWARE_APP", [3] = "POSITION_APP",
  [4] = "NODEINFO_APP", [5] = "ROUTING_APP", [6] = "ADMIN_APP", [7] = "TEXT_MESSAGE_COMPRESSED_APP",
  [8] = "WAYPOINT_APP", [9] = "AUDIO_APP", [10] = "DETECTION_SENSOR_APP", [11] = "ALERT_APP",
  [12] = "KEY_VERIFICATION_APP", [32] = "REPLY_APP", [33] = "IP_TUNNEL_APP", [34] = "PAXCOUNTER_APP",
  [64] = "SERIAL_APP", [65] = "STORE_FORWARD_APP", [66] = "RANGE_TEST_APP", [67] = "TELEMETRY_APP",
  [68] = "ZPS_APP", [69] = "SIMULATOR_APP", [70] = "TRACEROUTE_APP", [71] = "NEIGHBORINFO_APP",
  [72] = "ATAK_PLUGIN", [73] = "MAP_REPORT_APP", [74] = "POWERSTRESS_APP", [256] = "PRIVATE_APP",
}
-- portnum → protobuf message for Data.payload ("text" = UTF-8 string)
local PAYLOAD_TYPE = {
  [1] = "text", [11] = "text", [10] = "text", [32] = "text", [66] = "text",
  [3] = "meshtastic.Position", [4] = "meshtastic.User", [5] = "meshtastic.Routing",
  [6] = "meshtastic.AdminMessage", [8] = "meshtastic.Waypoint", [34] = "meshtastic.Paxcount",
  [65] = "meshtastic.StoreAndForward", [67] = "meshtastic.Telemetry", [70] = "meshtastic.RouteDiscovery",
  [71] = "meshtastic.NeighborInfo", [73] = "meshtastic.MapReport",
}

local mt = Proto("meshtastic", "Meshtastic")
local MF = {
  to = ProtoField.uint32("meshtastic.to", "To", base.HEX),
  from = ProtoField.uint32("meshtastic.from", "From", base.HEX),
  id = ProtoField.uint32("meshtastic.id", "Packet ID", base.HEX),
  flags = ProtoField.uint8("meshtastic.flags", "Flags", base.HEX),
  hop_limit = ProtoField.uint8("meshtastic.hop_limit", "Hop limit", base.DEC, nil, 0x07),
  want_ack = ProtoField.bool("meshtastic.want_ack", "Want ACK", 8, nil, 0x08),
  via_mqtt = ProtoField.bool("meshtastic.via_mqtt", "Via MQTT", 8, nil, 0x10),
  hop_start = ProtoField.uint8("meshtastic.hop_start", "Hop start", base.DEC, nil, 0xE0),
  channel_hash = ProtoField.uint8("meshtastic.channel_hash", "Channel hash", base.HEX),
  next_hop = ProtoField.uint8("meshtastic.next_hop", "Next hop (last byte)", base.HEX),
  relay_node = ProtoField.uint8("meshtastic.relay_node", "Relay node (last byte)", base.HEX),
  encrypted = ProtoField.bytes("meshtastic.encrypted", "Encrypted payload"),
  hops_away = ProtoField.uint8("meshtastic.hops_away", "Hops away"),
  pki = ProtoField.bool("meshtastic.pki", "PKI direct message"),
  decrypted = ProtoField.bytes("meshtastic.decrypted", "Decrypted Data (by LoRaSpy)"),
  portnum = ProtoField.uint32("meshtastic.portnum", "Portnum", base.DEC, PORTNUMS),
  text = ProtoField.string("meshtastic.text", "Text"),
}
mt.fields = MF

local function nodeid(n)
  if n == 0xFFFFFFFF then return "^all" end
  return string.format("!%08x", n)
end

function mt.dissector(tvb, pinfo, tree)
  if tvb:len() < 16 then return 0 end
  pinfo.cols.protocol = "Meshtastic"
  local t = tree:add(mt, tvb(), "Meshtastic")
  local to, from, id = tvb(0, 4):le_uint(), tvb(4, 4):le_uint(), tvb(8, 4):le_uint()
  t:add_le(MF.to, tvb(0, 4)):append_text(" (" .. nodeid(to) .. ")")
  t:add_le(MF.from, tvb(4, 4)):append_text(" (" .. nodeid(from) .. ")")
  t:add_le(MF.id, tvb(8, 4))
  local fl = t:add(MF.flags, tvb(12, 1))
  fl:add(MF.hop_limit, tvb(12, 1)); fl:add(MF.want_ack, tvb(12, 1))
  fl:add(MF.via_mqtt, tvb(12, 1)); fl:add(MF.hop_start, tvb(12, 1))
  local flags = tvb(12, 1):uint()
  local hop_start, hop_limit = (flags & 0xE0) >> 5, flags & 0x07
  if hop_start > 0 then t:add(MF.hops_away, hop_start - hop_limit):set_generated() end
  local chash = tvb(13, 1):uint()
  t:add(MF.channel_hash, tvb(13, 1))
  t:add(MF.next_hop, tvb(14, 1)); t:add(MF.relay_node, tvb(15, 1))
  if tvb:len() > 16 then t:add(MF.encrypted, tvb(16)) end

  local info = nodeid(from) .. " → " .. nodeid(to)
  set_endpoints(pinfo, nodeid(from), nodeid(to))
  local kv = sdrmon_kv()
  local plain = kv and hex_tvb(kv.plain, "Decrypted Data")
  if plain then
    if kv.method == "pki" then t:add(MF.pki, true):set_generated() end
    local dt = t:add(MF.decrypted, plain())
    pb(plain, pinfo, dt, "meshtastic.Data")
    local portnum, poff, plen = data_fields(plain)
    if portnum then
      t:add(MF.portnum, portnum):set_generated()
      local pname = PORTNUMS[portnum] or ("PORT_" .. portnum)
      info = info .. " [" .. (kv.channel or "?") .. "] " .. pname:gsub("_APP$", "")
      local ptype = PAYLOAD_TYPE[portnum]
      if poff and plen and plen > 0 then
        local ptvb = plain(poff, plen):tvb("Data.payload")
        if ptype == "text" then
          local s = ptvb:raw()
          t:add(MF.text, s):set_generated()
          info = info .. ": " .. s
        elseif ptype then
          pb(ptvb, pinfo, t:add(mt, ptvb(), pname .. " payload (" .. ptype .. ")"), ptype)
        end
      end
    end
  elseif chash == 0 and to ~= 0xFFFFFFFF then
    info = info .. " PKI (not decrypted)"
  else
    info = info .. string.format(" encrypted (channel hash 0x%02x)", chash)
  end
  pinfo.cols.info = info
  return tvb:len()
end

---------------------------------------------------------------------- MeshCore

local ROUTES = { [0] = "TRANSPORT_FLOOD", [1] = "FLOOD", [2] = "DIRECT", [3] = "TRANSPORT_DIRECT" }
local PTYPES = { [0] = "REQ", [1] = "RESPONSE", [2] = "TXT_MSG", [3] = "ACK", [4] = "ADVERT", [5] = "GRP_TXT",
                 [6] = "GRP_DATA", [7] = "ANON_REQ", [8] = "PATH", [9] = "TRACE", [10] = "MULTIPART",
                 [11] = "CONTROL", [15] = "RAW_CUSTOM" }
local ADV = { [1] = "chat", [2] = "repeater", [3] = "room server", [4] = "sensor" }

local mc = Proto("meshcore", "MeshCore")
local CF = {
  header = ProtoField.uint8("meshcore.header", "Header", base.HEX),
  route = ProtoField.uint8("meshcore.route", "Route type", base.DEC, ROUTES, 0x03),
  type = ProtoField.uint8("meshcore.type", "Payload type", base.DEC, PTYPES, 0x3C),
  version = ProtoField.uint8("meshcore.version", "Payload version", base.DEC, nil, 0xC0),
  tcode1 = ProtoField.uint16("meshcore.transport_code1", "Transport code 1", base.HEX),
  tcode2 = ProtoField.uint16("meshcore.transport_code2", "Transport code 2", base.HEX),
  path_len = ProtoField.uint8("meshcore.path_len", "Path length byte", base.HEX),
  hops = ProtoField.uint8("meshcore.hops", "Hops", base.DEC, nil, 0x3F),
  hash_size = ProtoField.uint8("meshcore.hash_size_code", "Hash size - 1", base.DEC, nil, 0xC0),
  path = ProtoField.bytes("meshcore.path", "Path"),
  payload = ProtoField.bytes("meshcore.payload", "Payload"),
  pubkey = ProtoField.bytes("meshcore.advert.public_key", "Public key"),
  ts = ProtoField.absolute_time("meshcore.advert.timestamp", "Timestamp", base.UTC),
  sig = ProtoField.bytes("meshcore.advert.signature", "Signature"),
  aflags = ProtoField.uint8("meshcore.advert.flags", "App flags", base.HEX),
  atype = ProtoField.uint8("meshcore.advert.type", "Node type", base.DEC, ADV, 0x0F),
  lat = ProtoField.double("meshcore.advert.lat", "Latitude"),
  lon = ProtoField.double("meshcore.advert.lon", "Longitude"),
  name = ProtoField.string("meshcore.advert.name", "Name"),
  chash = ProtoField.uint8("meshcore.channel_hash", "Channel hash", base.HEX),
  dest = ProtoField.uint8("meshcore.dest_hash", "Destination hash", base.HEX),
  src = ProtoField.uint8("meshcore.src_hash", "Source hash", base.HEX),
  mac = ProtoField.bytes("meshcore.mac", "Cipher MAC"),
  cipher = ProtoField.bytes("meshcore.ciphertext", "Ciphertext"),
  text = ProtoField.string("meshcore.text", "Text (decrypted by LoRaSpy)"),
  channel = ProtoField.string("meshcore.channel", "Channel"),
}
mc.fields = CF

function mc.dissector(tvb, pinfo, tree)
  if tvb:len() < 2 then return 0 end
  pinfo.cols.protocol = "MeshCore"
  local t = tree:add(mc, tvb(), "MeshCore")
  local h = tvb(0, 1):uint()
  local route, ptype = h & 3, (h >> 2) & 0x0F
  local ht = t:add(CF.header, tvb(0, 1))
  ht:add(CF.route, tvb(0, 1)); ht:add(CF.type, tvb(0, 1)); ht:add(CF.version, tvb(0, 1))
  local off = 1
  if route == 0 or route == 3 then
    t:add_le(CF.tcode1, tvb(off, 2)); t:add_le(CF.tcode2, tvb(off + 2, 2)); off = off + 4
  end
  local plen = tvb(off, 1):uint()
  local pt = t:add(CF.path_len, tvb(off, 1)); pt:add(CF.hops, tvb(off, 1)); pt:add(CF.hash_size, tvb(off, 1))
  off = off + 1
  local nbytes = (plen & 0x3F) * ((plen >> 6) + 1)
  if nbytes > 0 and off + nbytes <= tvb:len() then t:add(CF.path, tvb(off, nbytes)) end
  off = off + nbytes
  local info = (PTYPES[ptype] or ("TYPE_" .. ptype)) .. " " .. (ROUTES[route] or "?") ..
               ((plen & 0x3F) > 0 and (" path " .. (plen & 0x3F)) or "")
  local kv = sdrmon_kv() or {}
  if off < tvb:len() then
    local p = tvb(off)
    local st = t:add(CF.payload, p)
    if ptype == 4 and p:len() >= 100 then                  -- advert
      st:add(CF.pubkey, p(0, 32)); st:add_le(CF.ts, p(32, 4)); st:add(CF.sig, p(36, 64))
      if p:len() > 100 then
        local fl = p(100, 1):uint()
        local ft = st:add(CF.aflags, p(100, 1)); ft:add(CF.atype, p(100, 1))
        local i = 101
        if fl & 0x10 ~= 0 and p:len() >= i + 8 then
          st:add(CF.lat, p(i, 4), p(i, 4):le_int() / 1e6); st:add(CF.lon, p(i + 4, 4), p(i + 4, 4):le_int() / 1e6)
          i = i + 8
        end
        if fl & 0x20 ~= 0 then i = i + 2 end
        if fl & 0x40 ~= 0 then i = i + 2 end
        if fl & 0x80 ~= 0 and p:len() > i then
          local nm = p(i):string(ENC_UTF_8)
          st:add(CF.name, p(i), nm); info = info .. " " .. nm
        end
      end
      if kv.signature_ok then info = info .. (kv.signature_ok == "True" and " (sig ok)" or " (BAD SIG)") end
    elseif (ptype == 5 or ptype == 6) and p:len() >= 3 then  -- group text / data
      st:add(CF.chash, p(0, 1)); st:add(CF.mac, p(1, 2)); st:add(CF.cipher, p(3))
    elseif (ptype <= 2 or ptype == 8) and p:len() >= 4 then  -- direct
      st:add(CF.dest, p(0, 1)); st:add(CF.src, p(1, 1)); st:add(CF.mac, p(2, 2)); st:add(CF.cipher, p(4))
    end
  end
  if kv.channel then t:add(CF.channel, kv.channel):set_generated(); info = info .. " [" .. kv.channel .. "]" end
  if kv.text then t:add(CF.text, kv.text):set_generated(); info = info .. ": " .. kv.text end
  -- Source/Destination: advert name, channel, or the 1-byte key hashes of a direct message
  if ptype == 4 and kv.name then set_endpoints(pinfo, kv.name, "all")
  elseif kv.channel then set_endpoints(pinfo, kv.text and kv.text:match("^([^:]+):") or "?", kv.channel)
  elseif (ptype <= 2 or ptype == 8) and off + 2 <= tvb:len() then
    set_endpoints(pinfo, string.format("hash %02x", tvb(off + 1, 1):uint()), string.format("hash %02x", tvb(off, 1):uint()))
  else set_endpoints(pinfo, "MeshCore", "all") end
  pinfo.cols.info = info
  return tvb:len()
end

---------------------------------------------------------------------- LoRaSpy post-dissector

-- LoRaWAN fields (Wireshark's own dissector) for an Info summary, which it leaves empty
local LW = {
  mtype = Field.new("lorawan.msgtype"), devaddr = Field.new("lorawan.fhdr.devaddr"),
  fcnt = Field.new("lorawan.fhdr.fcnt"), fport = Field.new("lorawan.fport"),
  deveui = Field.new("lorawan.join_request.deveui"), devnonce = Field.new("lorawan.join_request.devnonce"),
}
local function lw_summary(kv)
  local m = LW.mtype()
  if not m then return nil end
  local parts = { tostring(m.display or m.value) }
  local de, dn, da, fc, fp = LW.deveui(), LW.devnonce(), LW.devaddr(), LW.fcnt(), LW.fport()
  if de then parts[#parts + 1] = "DevEUI " .. tostring(de.display or de.value) end
  if dn then parts[#parts + 1] = "DevNonce " .. tostring(dn.value) end
  if da then parts[#parts + 1] = string.format("DevAddr %08X", da.value) end
  if kv.device then parts[#parts + 1] = "(" .. kv.device .. ")" end
  if fc then parts[#parts + 1] = "FCnt " .. tostring(fc.value) end
  if fp then parts[#parts + 1] = "FPort " .. tostring(fp.value) end
  if kv.mic then parts[#parts + 1] = "MIC " .. kv.mic end
  return table.concat(parts, " ")
end

local sm = Proto("sdrmon", "LoRaSpy")
local SF = {
  rx = ProtoField.string("sdrmon.receiver", "Receiver"),
  snr = ProtoField.float("sdrmon.snr", "SNR (dB, measured)"),
  rssi_dbfs = ProtoField.float("sdrmon.rssi_dbfs", "RSSI (dBFS, in-band power over the frame)"),
  noise_dbfs = ProtoField.float("sdrmon.noise_dbfs", "Noise floor (dBFS)"),
  rssi_dbm = ProtoField.float("sdrmon.rssi_dbm", "RSSI (dBm, calibrated)"),
  bw = ProtoField.uint32("sdrmon.bandwidth", "Bandwidth (Hz)"),
  crc = ProtoField.string("sdrmon.crc", "CRC"),
  clipped = ProtoField.bool("sdrmon.clipped", "SDR ADC clipped (overloaded: lower the gain)"),
  channel = ProtoField.string("sdrmon.channel", "Channel / key"),
  method = ProtoField.string("sdrmon.method", "Decryption"),
  key = ProtoField.string("sdrmon.key", "Private key used"),
  identity = ProtoField.string("sdrmon.identity", "MeshCore identity used"),
  plain = ProtoField.bytes("sdrmon.plaintext", "Decrypted payload"),
  text = ProtoField.string("sdrmon.text", "Text"),
  device = ProtoField.string("sdrmon.device", "LoRaWAN device"),
  mic = ProtoField.string("sdrmon.mic", "LoRaWAN MIC"),
  decoded = ProtoField.string("sdrmon.decoded", "Decoded payload"),
  join = ProtoField.string("sdrmon.join_accept", "Join-accept"),
  dup = ProtoField.uint32("sdrmon.duplicate", "Seen before (times)"),
}
sm.fields = SF
local EX_CLIPPED = ProtoExpert.new("sdrmon.clipped.expert", "SDR overloaded during this frame: ADC clipped, "
                                   .. "bits may be wrong (lower the gain)", expert.group.PROTOCOL, expert.severity.WARN)
sm.experts = { EX_CLIPPED }

function sm.dissector(tvb, pinfo, tree)
  local kv = sdrmon_kv()
  if not kv then return end
  local lvl = kv.rssi_dbm and (kv.rssi_dbm .. " dBm") or (kv.rssi_dbfs and (kv.rssi_dbfs .. " dBFS")) or nil
  local t = tree:add(sm, "LoRaSpy: " .. (kv.rx or "") .. (lvl and (", RSSI " .. lvl) or "") ..
                         (kv.snr and (", SNR " .. kv.snr .. " dB") or "") ..
                         (kv.clipped and ", CLIPPED" or ""))
  if kv.clipped then
    t:add(SF.clipped, true)
    t:add_proto_expert_info(EX_CLIPPED)
  end
  if kv.rssi_dbfs and tonumber(kv.rssi_dbfs) then t:add(SF.rssi_dbfs, tonumber(kv.rssi_dbfs)) end
  if kv.noise_dbfs and tonumber(kv.noise_dbfs) then t:add(SF.noise_dbfs, tonumber(kv.noise_dbfs)) end
  if kv.rssi_dbm and tonumber(kv.rssi_dbm) then t:add(SF.rssi_dbm, tonumber(kv.rssi_dbm)) end
  if kv.rx then t:add(SF.rx, kv.rx) end
  if kv.snr and tonumber(kv.snr) then t:add(SF.snr, tonumber(kv.snr)) end
  if kv.bw and tonumber(kv.bw) then t:add(SF.bw, tonumber(kv.bw)) end
  if kv.crc then t:add(SF.crc, kv.crc) end
  if kv.channel then t:add(SF.channel, kv.channel) end
  if kv.method then t:add(SF.method, kv.method) end
  if kv.key then t:add(SF.key, kv.key) end
  if kv.identity then t:add(SF.identity, kv.identity) end
  if kv.plain and kv.plain ~= "" then t:add(SF.plain, ByteArray.new(kv.plain):tvb("plain")()) end
  if kv.text then t:add(SF.text, kv.text) end
  if kv.device then t:add(SF.device, kv.device) end
  if kv.mic then t:add(SF.mic, kv.mic) end
  if kv.decoded then t:add(SF.decoded, kv.decoded) end
  if kv.join_accept then t:add(SF.join, kv.join_accept) end
  if kv.dup and tonumber(kv.dup) then t:add(SF.dup, tonumber(kv.dup)) end
  if kv.proto == "lorawan" then
    local da, de, m = LW.devaddr(), LW.deveui(), LW.mtype()
    local dev = kv.device or (da and string.format("%08X", da.value)) or (de and tostring(de.display or de.value)) or "?"
    local up = not (m and tostring(m.display or m.value):find("Down")) and not (m and tostring(m.display or m.value):find("Accept"))
    set_endpoints(pinfo, up and dev or "network", up and "network" or dev)
    local info = lw_summary(kv) or tostring(pinfo.cols.info)
    if kv.join_accept then info = info .. "  JOIN ACCEPTED " .. kv.join_accept
    elseif kv.decoded then info = info .. "  → " .. kv.decoded
    elseif kv.plain then info = info .. "  → " .. kv.plain end
    pinfo.cols.info = info
  end
end
register_postdissector(sm)

---------------------------------------------------------------------- registration

local syncword = DissectorTable.get("loratap.syncword")
syncword:add(0x2B, mt)
syncword:add(0x12, mc)
