--
-- Thunder COM-RPC frame dissector plugin for Wireshark
--
-- Copyright (c) 2023 Metrological.
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; If not, see <http://www.gnu.org/licenses/>.
--

-- Configurables
INSTANCE_ID_SIZE = 4

CONNECTORS = {
 { "Thunder", 62000 },
 { "OCDM_Server", 63000 }
}

-- Constants
DIRECTION_OUTBOUND = 0
DIRECTION_INBOUND = 1
LABEL_ANNOUNCE = 1
LABEL_INVOKE = 2
ANNOUNCE_KIND_ACQUIRE = 0
ANNOUNCE_KIND_OFFER = 1
ANNOUNCE_KIND_REVOKE = 2
ANNOUNCE_KIND_REQUEST = 3

ERROR_CODES = {
  [0] = "ERROR_NONE",
  [1] = "ERROR_GENERAL",
  [2] = "ERROR_UNAVAILABLE",
  [3] = "ERROR_ASYNC_FAILED",
  [5] = "ERROR_ILLEGAL_STATE",
  [6] = "ERROR_OPENING_FAILED",
  [11] = "ERROR_TIMEDOUT",
  [12] = "ERROR_INPROGRESS",
  [17] = "ERROR_DESCTRUCTION_SUCCEEDED",
  [18] = "ERROR_DESTRUCTION_FAILED",
  [19] = "ERROR_CLOSING_FAILED",
  [22] = "ERROR_UNKNOWN_KEY",
  [25] = "ERROR_RPC_CALL_FAILED",
  [29] = "ERROR_DUPLICATE_KEY",
  [30] = "ERROR_BAD_REQUEST",
  [36] = "ERROR_ALREADY_RELEASED",
  [41] = "ERROR_INVALID_DESIGNATOR",
  [44] = "ERROR_NOT_SUPPORTED"
}

-- Global variables
G_INSTANCES = { [0] = "nullptr" }
G_IMPLEMENTATIONS = {}
G_PROCESSES = {}
G_RESPONSES = {}
G_REQUESTS = {}
G_PARAMS = {}
G_CALLSTACK = {}
G_CALL_LINES = {}
G_SIGNATURES = {}
G_TIMESTAMPS = {}


for i, _ in pairs(CONNECTORS) do
  G_PROCESSES[CONNECTORS[i][2]] = CONNECTORS[i][1]
end

Type = {
  STRING = 1,
  CHAR = 2,
  INT8 = 3,
  UINT8 = 4,
  INT16 = 5,
  UINT16 = 6,
  INT32 = 7,
  UINT32 = 8,
  INT64 = 9,
  UINT64 = 10,
  INTERFACE = 11,
  BUFFER8 = 12,
  BUFFER16 = 13,
  BUFFER32 = 14,
  BOOL = 15,
  ENUM8 = 16,
  ENUMU8 = 17,
  ENUM16 = 18,
  ENUMU16 = 19,
  ENUM32 = 20,
  ENUMU32 = 21,
  ENUM64 = 22,
  ENUMU64 = 23,
  OBJECT = 24,
  HRESULT = 25,
  POD = 26
}

SIZE_FOLLOWS = 0

TypeInfo = {
  [Type.CHAR] =       { size=1, kind="char" },
  [Type.INT8] =       { size=1, kind="int8_t", signed=true },
  [Type.UINT8] =      { size=1, kind="uint8_t", signed=false },
  [Type.INT16] =      { size=2, kind="int16_t", signed=true },
  [Type.UINT16] =     { size=2, kind="uint16_t", signed=false },
  [Type.INT32] =      { size=4, kind="int32_t", signed=true },
  [Type.UINT32] =     { size=4, kind="uint32_t", signed=false },
  [Type.INT64] =      { size=8, kind="int64_t", signed=true },
  [Type.UINT64] =     { size=8, kind="uint64_t", signed=false },
  [Type.STRING] =     { size=SIZE_FOLLOWS, kind="string", length=2 },
  [Type.INTERFACE] =  { size=4, kind="interface_id" },
  [Type.BOOL] =       { size=1, kind="bool" },
  [Type.BUFFER8] =    { size=SIZE_FOLLOWS, kind="buffer", length=1 },
  [Type.BUFFER16] =   { size=SIZE_FOLLOWS, kind="buffer", length=2 },
  [Type.BUFFER32] =   { size=SIZE_FOLLOWS, kind="buffer", length=4 },
  [Type.ENUM8] =      { size=1, kind="enum", signed=true },
  [Type.ENUMU8] =     { size=1, kind="enum", signed=false },
  [Type.ENUM16] =     { size=2, kind="enum", signed=true },
  [Type.ENUMU16] =    { size=2, kind="enum", signed=false },
  [Type.ENUM32] =     { size=4, kind="enum", signed=true },
  [Type.ENUMU32] =    { size=4, kind="enum", signed=false },
  [Type.ENUM64] =     { size=8, kind="enum", signed=true },
  [Type.ENUMU64] =    { size=8, kind="enum", signed=false },
  [Type.OBJECT] =     { size=INSTANCE_ID_SIZE, kind="object" },
  [Type.HRESULT] =    { size=4, kind="hresult", signed=false },
  [Type.POD] =        { size=0, kind="POD" }
}

-- Data
INTERFACES = {}
METHODS = {}
ENUMS = {}

-- IUnknown is a well-known interface
IUNKNOWN = 0
IUNKNOWN_METHODS = 3
INTERFACES[IUNKNOWN] = "Core::IUnknown"
METHODS[IUNKNOWN] = {
  [0] = { name = "AddRef" },
  [1] = { name = "Release", retvals = { { type = Type.HRESULT } }, params = { { name = "count", type = Type.UINT32, hide = true } } },
  [2] = { name = "QueryInterface", retvals = { { type = Type.OBJECT, interface_param = 1 } }, params = { { name = "interface", type = Type.INTERFACE } } }
}

-- Load rest of interface information
local function cwd()
    local path = debug.getinfo(2, "S").source:sub(2)
    return path:match("(.*[/\\])") or "./"
end
assert(loadfile(cwd() .. "protocol-thunder-comrpc.data"))(INTERFACES, METHODS, ENUMS, Type)

-- Protocol fields
-- Commons
f_source_process = ProtoField.string("thundercomrpc.source_process", "Source process", base.ASCII)
f_dest_process = ProtoField.string("thundercomrpc.dest_process", "Destination process", base.ASCII)
f_frame_request = ProtoField.framenum("thundercomrpc.frame_request", "Request", base.NONE, frametype.REQUEST)
f_frame_response = ProtoField.framenum("thundercomrpc.frame_response", "Response", base.NONE, frametype.RESPONSE)
f_frame_length = ProtoField.uint32("thundercomrpc.frame_length", "Frame size", base.DEC)
f_command = ProtoField.uint32("thundercomrpc.command", "Command", base.HEX)
f_direction = ProtoField.uint8("thundercomrpc.direction", "Direction", base.DEC, { [DIRECTION_INBOUND] = "Return", [DIRECTION_OUTBOUND] = "Call" }, 0x1)
f_label = ProtoField.uint8("thundercomrpc.label", "Label", base.DEC, { [LABEL_ANNOUNCE] = "Announce", [LABEL_INVOKE] = "Invoke" }, 0xFE)
f_instance = ProtoField.uint32("thundercomrpc.instance", "Instance", base.HEX)
f_instance_tag = ProtoField.string("thundercomrpc.instance_tag", "Instance tag", base.ASCII)
f_interface = ProtoField.uint32("thundercomrpc.interface", "Interface", base.HEX, INTERFACES)
f_payload_size = ProtoField.uint32("thundercomrpc.payload_size", "Payload size", base.DEC)
-- Announce only
f_process_id = ProtoField.uint32("thundercomrpc.announce.id", "ID", base.DEC)
f_exchange_id = ProtoField.uint32("thundercomrpc.announce.exchangeid", "Exchange ID", base.HEX)
f_version = ProtoField.uint32("thundercomrpc.announce.version", "Version", base.DEC)
f_class = ProtoField.string("thundercomrpc.announce.class", "Class", base.ASCII)
f_callsign = ProtoField.string("thundercomrpc.announce.callsign", "Callsign", base.ASCII)
f_kind = ProtoField.uint8("thundercomrpc.announce.kind", "Kind", base.DEC, { [0] = "Acquire", [1] = "Offer", [2] = "Revoke", [3] = "Request" } )
f_sequence = ProtoField.uint8("thundercomrpc.announce.sequence", "Sequence", base.DEC)
f_settings = ProtoField.string("thundercomrpc.announce.settings", "Settings", base.ASCII)
-- Invoke only
f_method = ProtoField.uint8("thundercomrpc.invoke.method", "Method", base.DEC)
f_method_text = ProtoField.string("thundercomrpc.invoke.method_text", "Method", base.ASCII)
f_return_values = ProtoField.string("thundercomrpc.invoke.return_values", "Return value", base.ASCII)
f_parameters = ProtoField.string("thundercomrpc.invoke.parameters", "Parameter", base.ASCII)
f_call_duration = ProtoField.string("thundercomrpc.invoke.call_duration", "Call duration", base.ASCII)
f_cached_addref = ProtoField.string("thundercomrpc.invoke.cached_addref", "Cached AddRef", base.ASCII)
f_cached_release = ProtoField.string("thundercomrpc.invoke.cached_release", "Cached Release", base.ASCII)
f_hresult = ProtoField.uint32("thundercomrpc.invoke.hresult", "hresult", base.DEC)

-- Protocol definition
thunder_protocol_tcp = Proto("Thunder-COMRPC", "Thunder COM-RPC Protocol")
thunder_protocol_tcp.fields = { f_source_process, f_dest_process, f_frame_request, f_frame_response, f_frame_length, f_command, f_direction,
  f_label, f_instance, f_instance_tag, f_interface, f_process_id, f_exchange_id, f_version, f_class, f_callsign, f_kind, f_sequence, f_settings,
  f_method, f_method_text, f_return_values, f_parameters, f_call_duration, f_payload_size, f_cached_addref, f_cached_release, f_hresult }


-- Reads a packed integer value
function read_varint(buffer)
  local offset = 0
  local value = 0
  local v = 0

  repeat
    v = buffer(offset, 1):uint()
    value = bit32.bor(value, bit32.lshift(bit32.band(v, 0x7f), (7 * offset)))
    offset = (offset + 1)
  until (bit32.band(v, 0x80) == 0)

  return value, offset
end

-- Constructs a unique channel ID
function channel_id(source, dest)
  return bit32.bor(bit32.lshift(source, 16), dest)
end

-- Looks up a method signature
function method_signature(interface, method)
  local signature = nil

  if method < IUNKNOWN_METHODS then
    signature = METHODS[IUNKNOWN][method]
  elseif METHODS[interface] and METHODS[interface][method] then
    signature = METHODS[interface][method]
  end

  return signature
end

-- Formats a parameter value
function parameter(typeinfo, buffer, is_ret_val)
  local value = nil

  local typeid = typeinfo.type
  local size = TypeInfo[typeid].size
  local data_buffer = buffer(0, size)
  local signed = TypeInfo[typeid].signed
  local kind = TypeInfo[typeid].kind
  local name = typeinfo.name
  local data = 0

  if (size ~= SIZE_FOLLOWS) and (size ~= 0) then
    -- Have fixed size field
    if signed == true then
      data = data_buffer:int()
    else
      data = data_buffer:uint()
    end

    if signed ~= nil then
      -- This is an integer value
      value = tostring(data)

      -- Add extra information if it's an enum or hresult
      if TypeInfo[typeid].kind == "enum" then
        if typeinfo.enum then
          kind = (kind .. " " .. typeinfo.enum)

          if ENUMS[typeinfo.enum] then
            value = (value .. " '" .. ENUMS[typeinfo.enum][data] .. "'")
          end
        end

      elseif typeid == Type.HRESULT then
        if ERROR_CODES[data] then
          value = (value .. " 'Core::" .. ERROR_CODES[data] .. "'")
        end
      end
    end
  end

  if not value then
    if typeid == Type.CHAR then
      value = ("'" .. string.char(data) .. "'")

    elseif typeid == Type.BOOL then
      if buffer(0, size):uint() ~= 0 then
        value = "true"
      else
        value = "false"
      end

    elseif typeid == Type.OBJECT then
      if typeinfo.class then
        kind = (kind .. " " .. typeinfo.class .. " *")
      end

      if G_INSTANCES[data] and G_INSTANCES[data] ~= "" then
        value = string.format("0x%08x '%s'", data, G_INSTANCES[data])
      else
        value = string.format("0x%08x", data)
      end

    elseif typeid == Type.INTERFACE then
      if INTERFACES[data] then
        value = string.format("0x%08x '%s'", data, INTERFACES[data])
      else
        value = string.format("0x%08x", data)
      end

    elseif typeid == Type.STRING then
      local length = TypeInfo[typeid].length
      local string_size = buffer(0, length):uint()
      if string_size > 0 then
        value = string.format("\"%s\"", buffer(length, string_size):raw())
      else
        value = "\"\""
      end
      size = (length + string_size)

    elseif (typeid == Type.BUFFER8) or (typeid == Type.BUFFER16) or (typeid == Type.BUFFER32) then
      local length = TypeInfo[typeid].length
      local offset = 0
      local buffer_size = buffer(0, length):uint()

      if buffer_size > 0 then
        -- This looks overengineered...
        if is_ret_val and typeinfo.length_param then
          offset = 2
        end

        value = buffer(offset + length, buffer_size):bytes():tohex()
      else
        value = "nil"
      end

      size = (offset + length + buffer_size)
    end
   end

  return size, value, data, kind, typeid, name
end

-- Creates a table of strings representing the method's parameters (or return values)
function method_dissect_params(param_list, buffer, is_ret_val)
  local params = {}
  local offset = 0

  if buffer and param_list then
    for _, typeinfo in pairs(param_list) do

      if typeinfo.length == nil then
        local size = 0

        if typeinfo.type ~= Type.POD then
          local size, value, data, kind, typeid, name = parameter(typeinfo, buffer(offset, buffer:len() - offset), is_ret_val)

          if value then
            table.insert(params, { offset=offset, size=size, typeinfo=typeinfo, value=value, data=data, kind=kind, typeid=typeid, name=name })
          end

          offset = (offset + size)

        else
          -- Recursively dissect PODs..
          local pod_params, pod_size = method_dissect_params(typeinfo.pod, buffer(offset, buffer:len() - offset), is_ret_val)

          for _, val in pairs(pod_params) do
            val.name = typeinfo.name .. "." .. val.name
            table.insert(params, val)
          end

          offset = (offset + size)
        end
      end
    end
  end

  return params, offset
end

-- Finds method's parameters
function method_params(signature, buffer)
  local params = {}
  local name = nil
  local size = 0

  if signature then
    name = signature.name

    if signature.params then
      params, size = method_dissect_params(signature.params, buffer, false)
    end
  end

  if params then
    for _, param in pairs(params) do
      if param.kind == "object" then
        param.kind = param.kind .. " " .. params[param.typeinfo.interface_param].data
       end
    end
  end

  return name, params, size
end

-- Finds method's return values
function method_return_value(signature, buffer, input_params)
  local params = {}
  local name = nil
  local size = 0

  if signature then
    name = signature.params

    if signature.retvals then
      params, size = method_dissect_params(signature.retvals, buffer, true)
    end
  end

  if params then
    for _, param in pairs(params) do
      if param.kind == "object" then
        param.kind = param.kind .. " " .. INTERFACES[input_params[param.typeinfo.interface_param].data] .. " *"
      end
    end
  end

  return name, params, size
end

-- Make sure not to display linefeed characters in the info column...
function multiline_text(text)
  local idx = string.find(text, "\n")
  if text:len() > 48 then
    text = text:sub(1, 48) .. " (...)"
  end
  if idx then
    return text:gsub("\n", " ")
  else
    return text
  end
end

G_PDUS = {}

-- PDU dissector
function thunder_protocol_pdu_dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()
  local dummy_buffer = buffer(0, 0)

  pinfo.cols.protocol = thunder_protocol_tcp.name
  pinfo.cols.info = ""

  local source_id = pinfo.src_port
  local dest_id = pinfo.dst_port
  local frame = pinfo.number

  local offset = 0

  -- Read packed length
  local length, length_size = read_varint(buffer(offset, math.min(buffer_length, 4)))
  local length_offset = offset
  offset = (offset + length_size)

  -- Read command
  local command, command_size, command_offset = read_varint(buffer(offset, math.min(buffer_length - offset, 4)))
  local command_offset = offset
  local direction = bit32.band(command, 0x1)
  local label = bit32.rshift(command, 1)
  offset = (offset + command_size)

  -- After the preamble the data will differ for invoke/announce and inbound/outbound
  local payload_offset = offset
  local payload_size = (buffer_length - payload_offset)
  local payload_buffer = buffer(payload_offset, payload_size)

  -- Create the subtree for this protocol
  local headline = "Thunder COM-RPC Protocol,"
  if direction == DIRECTION_OUTBOUND then
    headline = headline .. " outbound message"
  else
    headline = headline .. " inbound message"
  end

  local subtree = tree:add(thunder_protocol_tcp, buffer(), headline)

  if G_PROCESSES[source_id] ~= nil then
    subtree:add(f_source_process, dummy_buffer, G_PROCESSES[source_id]):set_generated(true)
  end

  if G_PROCESSES[dest_id] ~= nil then
    subtree:add(f_dest_process, dummy_buffer, G_PROCESSES[dest_id]):set_generated(true)
  end

  subtree:add(f_frame_length, buffer(length_offset, length_size), length)
  subtree:add(f_label, buffer(command_offset, command_size) )
  subtree:add(f_direction, buffer(command_offset, command_size), direction)
  subtree:add(f_payload_size, dummy_buffer, payload_size):set_generated(true)

  local cols_info = ""

  if direction == DIRECTION_OUTBOUND then
    if G_TIMESTAMPS[frame] == nil then
      G_TIMESTAMPS[frame] = pinfo.rel_ts
    end

    -- Read instance pointer and interface number
    local instance = payload_buffer(0, INSTANCE_ID_SIZE):uint()
    local interface = 0

    if label == LABEL_INVOKE then
      interface = payload_buffer(4, 4):uint()
    elseif label == LABEL_ANNOUNCE then
      interface = payload_buffer(8, 4):uint()
    end

    -- Enumerate instances to give them an alias (name of the interface followed by a counter letter)
    if (instance ~= 0) and ((G_INSTANCES[instance] == nil) or (G_INSTANCES[instance]:len() == 0)) then
      local impl = "impl"

      if INTERFACES[interface] ~= nil then
        local idx = INTERFACES[interface]:reverse():find("I::")
        impl = INTERFACES[interface]:sub(1 - idx)
      end

      if G_IMPLEMENTATIONS[impl] == nil then
        G_IMPLEMENTATIONS[impl] = 0
      end

      G_IMPLEMENTATIONS[impl] = (G_IMPLEMENTATIONS[impl] + 1)
      G_INSTANCES[instance] = (string.lower(impl) .. "_" .. string.char(G_IMPLEMENTATIONS[impl] + 64))
    end

    if label == LABEL_INVOKE then
      if G_RESPONSES[frame] == nil then
        -- Put this call on stack, will know the response frame number once it appears...
        local channel = channel_id(source_id, dest_id)

        if G_CALLSTACK[channel] == nil then
          G_CALLSTACK[channel] = {}
        end

        table.insert(G_CALLSTACK[channel], 1, frame)
      else
        -- This is not the first pass, so we finally know the response frame number
        subtree:add(f_frame_response, dummy_buffer, G_RESPONSES[frame]):set_text("Response to this COM-PRC call is in frame: " .. G_RESPONSES[frame]):set_generated(true)
      end

      local param_buffer = nil
      if payload_size > 9 then
        param_buffer = payload_buffer(9, payload_size - 9)
      end

      local method_no = payload_buffer(8, 1):uint()
      local method_info = method_signature(interface, method_no)
      local method_name, params, size = method_params(method_info, param_buffer)

      offset = (offset + size)

      if not method_name then
        method_name = ("{method:" .. method .. "}")
      end

      subtree:add(f_instance, payload_buffer(0, INSTANCE_ID_SIZE))
      subtree:add(f_instance_tag, payload_buffer(0, INSTANCE_ID_SIZE), G_INSTANCES[instance]):set_generated(true)
      subtree:add(f_interface, payload_buffer(INSTANCE_ID_SIZE, 4))
      subtree:add(f_method_text, payload_buffer((INSTANCE_ID_SIZE + 4), 1), method_name):append_text(" (" .. tostring(method_no) .. ")")

      -- Build params list
      local params_text = ""

      for _, param in pairs(params) do
        local text = ""

        if param.name then
          text = ("(" .. param.kind .. ") " .. param.name .. " = " .. param.value)

          if not param.typeinfo.hide then
            params_text = (params_text .. param.name .. "=" .. multiline_text(param.value) .. ", ")
          end
        else
          text = ("(" .. param.kind .. ") " .. param.value)

          if not param.typeinfo.hide then
            params_text = (params_text .. multiline_text(param.value) .. ", ")
          end
        end

        subtree:add(f_parameters, payload_buffer(9 + param.offset, param.size), text)
      end

      params_text = string.sub(params_text, 1, -3)

      -- Construct the call line and cache it so it can be used with the return call
      local call_line = string.format("%s->%s(%s)", G_INSTANCES[instance], method_name, params_text)
      cols_info = (call_line .. " called")

      G_PARAMS[frame] = params
      G_CALL_LINES[frame] = call_line
      G_SIGNATURES[frame] = method_info

    elseif label == LABEL_ANNOUNCE then
      if G_RESPONSES[frame] == nil then
        -- Put this call on stack, will know the response frame number once it appears...
        local channel = channel_id(source_id, dest_id)

        if G_CALLSTACK[channel] == nil then
          G_CALLSTACK[channel] = {}
        end

        table.insert(G_CALLSTACK[channel], 1, frame)
      else
        -- This is not the first pass, so we finally know the response frame number
        subtree:add(f_frame_response, dummy_buffer, G_RESPONSES[frame]):set_text("Response to this COM-PRC call is in frame: " .. G_RESPONSES[frame]):set_generated(true)
      end

      local class = nil
      local callsign = nil

      local class_length = payload_buffer((INSTANCE_ID_SIZE + 17), 2):uint()
      if class_length > 0 then
        class = payload_buffer((INSTANCE_ID_SIZE + 19), class_length):raw()
        subtree:add(f_class, payload_buffer((INSTANCE_ID_SIZE + 19), class_length))
      end

      local callsign_length = payload_buffer((INSTANCE_ID_SIZE + 19 + class_length), 2):uint()
      if callsign_length > 0 then
        callsign = payload_buffer((INSTANCE_ID_SIZE + 21 + class_length), callsign_length):raw()
        subtree:add(f_callsign, payload_buffer((INSTANCE_ID_SIZE + 21 + class_length), callsign_length))
      end

      -- Determine the process name
      if G_PROCESSES[source_id] == nil then
        if callsign then
          G_PROCESSES[source_id] = callsign
        elseif class then
          G_PROCESSES[source_id] = class
        else
          G_PROCESSES[source_id] = string.format("WPEProcess[%u]", payload_buffer(4,4):uint())
        end
      end

      if payload_buffer(0, INSTANCE_ID_SIZE):uint() ~= 0 then
        subtree:add(f_instance, payload_buffer(0, INSTANCE_ID_SIZE))
        subtree:add(f_instance_tag, payload_buffer(0, INSTANCE_ID_SIZE), G_INSTANCES[instance]):set_generated(true)
      end

      subtree:add(f_process_id, payload_buffer(INSTANCE_ID_SIZE, 4))

      if payload_buffer((INSTANCE_ID_SIZE + 4), 4):uint() ~= 0xFFFFFFFF then
        subtree:add(f_interface, payload_buffer((INSTANCE_ID_SIZE + 4), 4))
      end

      if payload_buffer((INSTANCE_ID_SIZE + 12), 4):uint() ~= 0xFFFFFFFF then
        subtree:add(f_version, payload_buffer(16, 4))
      end

      subtree:add(f_kind, payload_buffer((INSTANCE_ID_SIZE + 16), 1))

      local kind = payload_buffer((INSTANCE_ID_SIZE + 16), 1):uint()
      if kind == ANNOUNCE_KIND_ACQUIRE then
        cols_info = string.format("Acquire: class %s, interface %s", payload_buffer((INSTANCE_ID_SIZE + 19), class_length):raw(),INTERFACES[interface])
      elseif kind == ANNOUNCE_KIND_OFFER then
        cols_info = string.format("Offer: interface %s, instance 0x%08x '%s'", INTERFACES[interface], instance, G_INSTANCES[instance])
      elseif kind == ANNOUNCE_KIND_REVOKE then
        cols_info = string.format("Revoke: interface %s, instance 0x%08x '%s'", INTERFACES[interface], instance, G_INSTANCES[instance])
      elseif kind == ANNOUNCE_KIND_REQUEST then
        cols_info = string.format("Request: interface %s, instance 0x%08x '%s'", INTERFACES[interface], instance, G_INSTANCES[instance])
      end

      -- Done with the announce message, advance...
      offset = (offset + INSTANCE_ID_SIZE + (4 * 4) + 1 + class_length + 2 + callsign_length + 2)
    end

  elseif direction == DIRECTION_INBOUND then
    if G_REQUESTS[frame] == nil then
      -- Pick up the first frame number that was put on the call stack
      -- and cache the tied request with response, it will be used once the request is updated
      local channel = channel_id(dest_id, source_id)
      G_REQUESTS[frame] = G_CALLSTACK[channel][1]
      G_RESPONSES[G_REQUESTS[frame]] = frame
      table.remove(G_CALLSTACK[channel], 1)
    end

    local duration_rel_ts = (pinfo.rel_ts - G_TIMESTAMPS[G_REQUESTS[frame]])
    local duration = string.format("%.6f", duration_rel_ts):gsub(",",".")

    -- We always know the request frame
    subtree:add(f_frame_request, buffer(0,0), G_REQUESTS[frame]):set_text("This is a response to the COM-RPC call in frame: " .. G_REQUESTS[frame]):set_generated(true)
    subtree:add(f_call_duration, buffer(0,0), duration):set_text(string.format("Time elapsed since invoke: %s seconds", duration)):set_generated(true)

    if label == LABEL_INVOKE then
      local return_value_buffer = nil
      if payload_size > 0 then
        return_value_buffer = payload_buffer(0, payload_size)
      end

      local signature = G_SIGNATURES[G_REQUESTS[frame]]
      local _, params, size = method_return_value(signature, return_value_buffer, G_PARAMS[G_REQUESTS[frame]])

      local params_text = ""

      local hresult = nil

      for _, param in pairs(params) do
        local text = ""

        if param.name then
          text = ("(" .. param.kind .. ") " .. param.name .. " = " .. param.value)
          params_text = (params_text .. param.name .. "=" .. multiline_text(param.value) .. ", ")
        else
          text = ("(" .. param.kind .. ") " .. param.value)
          params_text = (params_text .. multiline_text(param.value) .. ", ")
        end

        if hresult == nil and param.typeid == Type.HRESULT then
          hresult = payload_buffer(param.offset, param.size):uint()
          subtree:add(f_hresult, payload_buffer(param.offset, param.size)):set_generated(true)
        end

        subtree:add(f_return_values, payload_buffer(param.offset, param.size), text)
      end

      params_text = string.sub(params_text, 1, -3)

      local request_text
      if G_REQUESTS[frame] and G_CALL_LINES[G_REQUESTS[frame]] then
        request_text = G_CALL_LINES[G_REQUESTS[frame]]
      else
        request_text = "<unknown>"
      end

      cols_info = request_text .. " returned " .. params_text
      offset = (offset + size)

      local overlay_offset = size
      while overlay_offset < payload_size do
        local instance = payload_buffer(overlay_offset, INSTANCE_ID_SIZE):uint()
        local id = payload_buffer((overlay_offset + INSTANCE_ID_SIZE), 4):uint()
        local how = payload_buffer((overlay_offset + INSTANCE_ID_SIZE + 4), 1):uint()
        local target = string.format("(%s *) 0x%08x '%s'", INTERFACES[id], instance, G_INSTANCES[instance])

        if how == 1 then
          subtree:add(f_cached_addref, payload_buffer(overlay_offset, (5 + INSTANCE_ID_SIZE)), target)
        elseif how == 2 then
          subtree:add(f_cached_release, payload_buffer(overlay_offset, (5 + INSTANCE_ID_SIZE)), target)
        end

        overlay_offset = (overlay_offset + 5 + INSTANCE_ID_SIZE)
      end

    elseif label == LABEL_ANNOUNCE then
      subtree:add(f_sequence, payload_buffer(4, 4))

      -- Read the three configuration strings (just display as they are)
      local offs = 8
      for i = 1, 3 do
        local size = payload_buffer(offs, 2):uint()
        if size ~= 0 then
          subtree:add(f_settings, payload_buffer(offs + 2, size))
        end
        offs = (offs + 2 + size)
      end

      offset = (offset + offs)

      cols_info = ("connection ID " .. payload_buffer(4, 4):uint())
    end

  end

  if not G_PDUS[frame] then
    -- Ensure the table always exists
    G_PDUS[frame] = {}
    G_PDUS[frame].count = 1
    G_PDUS[frame].info = {}
  end

  table.insert(G_PDUS[frame].info, cols_info)

  return offset
end

-- PDU length detector
function thunder_protocol_get_pdu_length(buffer, pinfo, offset)
  local frame = pinfo.number

  -- Firstly pick up the PDU frame length Wireshark is asking for
  local buffer_length = buffer:len()
  local length, length_size = read_varint(buffer(offset, math.min(buffer_length - offset, 4)))
  local pdu_length = (length + length_size)

  -- However if it's the first call, let's see how many PDU's are in the frame really
  if not G_PDUS[frame] then
    offset = (offset + pdu_length)

    local count = 1

    while offset < buffer_length do
      local length, length_size = read_varint(buffer(offset, math.min(buffer_length - offset, 4)))
      offset = (offset + (length + length_size))
      count = (count + 1)
    end

    G_PDUS[frame] = {}
    G_PDUS[frame].count = count
    G_PDUS[frame].info = {}
  end

  return pdu_length
end

-- The Thunder COM-RPC protocol dissector
function thunder_protocol_tcp.dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()

  if buffer_length == 0 then
    return
  end

  local frame = pinfo.number

  -- Reset the PDU information
  G_PDUS = { }

  dissect_tcp_pdus(buffer, tree, 2, thunder_protocol_get_pdu_length, thunder_protocol_pdu_dissector, true)

  local info = ""

  -- Handle multiple PDUs in a single frame, too
  if G_PDUS[frame].count > 1 then
    for key, value in pairs(G_PDUS[frame].info) do
      if key > 1 then
        info = (info .. ", ")
      end
      info = (info .. "[" .. key .. "] " .. value)
    end
  else
    info = G_PDUS[frame].info[1]
  end

  pinfo.cols["info"] = info
end

for _, connector in pairs(CONNECTORS) do
  dissector_tcp = DissectorTable.get("tcp.port")
  dissector_tcp:add(connector[2], thunder_protocol_tcp)
end
