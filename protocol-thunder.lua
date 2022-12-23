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

require "_protocol-thunder_types"


-- IUnknown is a well-known interface

IUNKNOWN = 0

INTERFACES[IUNKNOWN] = "Core::IUnknown"

METHODS[IUNKNOWN] = {
  [0] = { name = "AddRef" },
  [1] = { name = "Release", retvals = { Type.UINT32 } },
  [2] = { name = "QueryInterface", retvals = { Type.INSTANCE }, params = { Type.INTERFACE } }
}

-- Pick up the rest of interfaces from the generated file
require "_protocol-thunder_generated_data"


-- Constants
THUNDER_COM_PORT = 62000
DIRECTION_OUTBOUND = 0
DIRECTION_INBOUND = 1
LABEL_ANNOUNCE = 1
LABEL_INVOKE = 2

-- Global variables
G_INSTANCES = { [0] = "nullptr" }
G_IMPLEMENTATIONS = {}
G_PROCESSES = { [THUNDER_COM_PORT] = "WPEFramework" }
G_RESPONSES = {}
G_REQUESTS = {}
G_CALLSTACK = {}
G_CALL_LINES = {}
G_SIGNATURES = {}
G_TIMESTAMPS = {}

-- Protocol fields
-- Commons:
f_source_process = ProtoField.string("thundercomrpc.source_process", "Source process", base.ASCII)
f_dest_process = ProtoField.string("thundercomrpc.dest_process", "Destination process", base.ASCII)
f_frame_request = ProtoField.framenum("thundercomrpc.frame_request", "Request", base.NONE, frametype.REQUEST)
f_frame_response = ProtoField.framenum("thundercomrpc.frame_response", "Response", base.NONE, frametype.RESPONSE)
f_frame_length = ProtoField.uint32("thundercomrpc.frame_length", "Frame size", base.DEC)
f_command = ProtoField.uint32("thundercomrpc.command", "Command", base.HEX)
f_direction = ProtoField.uint8("thundercomrpc.direction", "Direction", base.DEC, { [DIRECTION_INBOUND] = "Return", [DIRECTION_OUTBOUND] = "Call" }, 0x1)
f_label = ProtoField.uint32("thundercomrpc.label", "Label", base.DEC, { [LABEL_ANNOUNCE] = "Announce", [LABEL_INVOKE] = "Invoke" }, 0xFFFFFFFE)
f_instance = ProtoField.uint32("thundercomrpc.instance", "Instance", base.HEX)
f_instance_tag = ProtoField.string("thundercomrpc.instance_tag", "Instance tag", base.ASCII)
f_interface = ProtoField.uint32("thundercomrpc.interface", "Interface", base.HEX, INTERFACES)
f_payload_size = ProtoField.uint32("thundercomrpc.payload_size", "Payload size", base.DEC)
f_data = ProtoField.bytes("thundercomrpc.data", "Data")
f_no_data = ProtoField.string("thundercomrpc.no_data", "No data", base.ASCII)
-- Announce only:
f_process_id = ProtoField.uint32("thundercomrpc.announce.id", "ID", base.DEC)
f_exchange_id = ProtoField.uint32("thundercomrpc.announce.exchangeid", "Exchange ID", base.HEX)
f_version = ProtoField.uint32("thundercomrpc.announce.version", "Version", base.DEC)
f_class = ProtoField.stringz("thundercomrpc.announce.class", "Class", base.ASCII)
f_kind = ProtoField.uint8("thundercomrpc.announce.kind", "Kind", base.DEC, { [0] = "Acquire", [1] = "Offer", [2] = "Revoke", [3] = "Request" } )
f_sequence = ProtoField.uint8("thundercomrpc.announce.sequence", "Sequence", base.DEC)
f_settings = ProtoField.string("thundercomrpc.announce.settings", "Settings", base.ASCII)
-- Invoke only:
f_method = ProtoField.uint8("thundercomrpc.invoke.method", "Method", base.DEC)
f_method_text = ProtoField.string("thundercomrpc.invoke.method_text", "Method", base.ASCII)
f_prototype = ProtoField.string("thundercomrpc.invoke.prototype", "Prototype", base.ASCII)
f_return_value = ProtoField.string("thundercomrpc.invoke.return_value", "Return value", base.ASCII)
f_parameters = ProtoField.string("thundercomrpc.invoke.parameters", "Parameters", base.ASCII)
f_call_duration = ProtoField.string("thundercomrpc.invoke.call_duration", "Call duration")

-- Protocol definition:
thunder_protocol_tcp = Proto("Thunder-COMRPC", "Thunder COM-RPC Protocol")
thunder_protocol_tcp.fields = { f_source_process, f_dest_process, f_frame_request, f_frame_response, f_frame_length, f_command, f_direction,
  f_label, f_instance, f_instance_tag, f_interface, f_data, f_no_data, f_process_id, f_exchange_id, f_version, f_class, f_kind, f_sequence, f_settings,
  f_method, f_method_text, f_return_value, f_parameters, f_call_duration, f_payload_size }


-- Reads a packed integer value
function read_varint(buffer)
  local offset = 0
  local value = 0
  local v = 0

  repeat
    v = buffer(offset,1):uint()
    value = bit32.bor(value, bit32.lshift(bit32.band(v, 0x7f), (7 * offset)))
    offset = offset + 1
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

  if method < 3 then
    signature = METHODS[IUNKNOWN][method]
  elseif METHODS[interface] then
    signature = METHODS[interface][method]
  end

  return signature
end

-- Formats a parameter value
function parameter(typeid, buffer)
  local value = nil

  local size = TypeInfo[typeid].size
  local data_buffer = buffer(0, size)
  local signed = TypeInfo[typeid].signed

  if size ~= 0 then
    if signed == true then
      data = data_buffer:int()
    else
      data = data_buffer:uint()
    end

    if signed ~= nil then
      value = tostring(data)
    end
  end

  if not value then
    if typeid == Type.CHAR then
      value = string.char(data)
    elseif typeid == Type.INSTANCE then
      value = string.format("0x%08x '%s'", data, G_INSTANCES[data])
    elseif typeid == Type.INTERFACE and INTERFACES[data] then
      value = string.format("0x%08x '%s'", data, INTERFACES[data])
    elseif typeid == Type.STRING then
      local string_size = buffer(0,2):uint()
      value = string.format("\"%s\"", buffer(2, string_size):raw())
      size = (2 + string_size)
    end
  end

  return size, value
end

-- Creates a table of strings representing the method's parameters (or return values)
function method_dissect_params(param_list, buffer)
  local params = {}
  local offset = 0

  if buffer and param_list then
    for _, typeid in pairs(param_list) do

      local size, value = parameter(typeid, buffer(offset, buffer:len() - offset))

      if value then
        table.insert(params, { offset=offset, size=size, typeid=typeid, value=value })
      end

      offset = (offset + size)
    end
  end

  return params
end

-- Finds a method's parameters
function method_params(signature, buffer)
  local params = {}
  local name = "_unknown_"

  if signature then
    name = signature.name

    if signature.params then
      params = method_dissect_params(signature.params, buffer)
    end
  end

  return name, params
end

-- Finds a method's return values
function method_return_value(signature, buffer)
  local params = {}
  local name = "_unknown_"

  if signature then
    name = signature.params

    if signature.retvals then
      params = method_dissect_params(signature.retvals, buffer)
    end
  end

  return name, params
end

-- Make sure not to display linefeed characters in the info column...
function multiline_text(text)
  if string.find(text, "\n") then
    return "<multi-line-string>"
  else
    return text
  end
end

-- The the Thunder COM-RPC protocol dissector
function thunder_protocol_tcp.dissector(buffer, pinfo, tree)
  local buffer_length = buffer:len()

  if buffer_length == 0 then
    return
  end

  pinfo.cols.protocol = thunder_protocol_tcp.name
  pinfo.cols.info = ""

  local source_id = pinfo.src_port
  local dest_id = pinfo.dst_port
  local frame = pinfo.number

  local offset = 0

  -- Read packed length
  local length, length_size = read_varint(buffer(offset, 4))
  local length_offset = offset
  offset = (offset + length_size)

  -- Read command
  local command, command_size, command_offset = read_varint(buffer(offset, 4))
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
    subtree:add(f_source_process, payload_buffer(0, 0), G_PROCESSES[source_id]):set_generated(true)
  end

  if G_PROCESSES[dest_id] ~= nil then
    subtree:add(f_dest_process, payload_buffer(0, 0), G_PROCESSES[dest_id]):set_generated(true)
  end

  subtree:add(f_frame_length, buffer(length_offset, length_size), length)
  subtree:add(f_label, buffer(command_offset, command_size) )
  subtree:add(f_direction, buffer(command_offset, command_size), direction)
  subtree:add(f_payload_size, buffer(0,0), payload_size):set_generated(true)

  if direction == DIRECTION_OUTBOUND then

    if G_RESPONSES[frame] == nil then
      -- Put this call on stack, will know the response frame number once it appears...
      local channel = channel_id(source_id, dest_id)
      if G_CALLSTACK[channel] == nil then
        G_CALLSTACK[channel] = {}
      end

      table.insert(G_CALLSTACK[channel], 1, frame)
    else
      -- This is not the first pass, so we finally know the response frame number
      subtree:add(f_frame_response, payload_buffer(0,0), G_RESPONSES[frame]):set_text("Response to this COM-PRC call is in frame: " .. G_RESPONSES[frame]):set_generated(true)
    end

    if G_TIMESTAMPS[frame] == nil then
      G_TIMESTAMPS[frame] = pinfo.rel_ts
    end

    -- Read instance pointer and interface number
    local instance = 0
    local interface = 0
    if label == LABEL_INVOKE then
      instance = payload_buffer(0, 4):uint()
      interface = payload_buffer(4, 4):uint()
    elseif label == LABEL_ANNOUNCE then
      instance = payload_buffer(4, 4):le_uint()
      interface = payload_buffer(8,4):le_uint()
    end

    if (instance ~= 0) and ((G_INSTANCES[instance] == nil) or (G_INSTANCES[instance] == "")) then
      -- Enumerate instances to give them an alias (name of the interface followed by a counter letter)
      if INTERFACES[interface] ~= nil then
        local impl = string.gsub(INTERFACES[interface], "Exchange::I", "")
        if G_IMPLEMENTATIONS[impl] == nil then
          G_IMPLEMENTATIONS[impl] = 0
        end
        G_IMPLEMENTATIONS[impl] = G_IMPLEMENTATIONS[impl] + 1

        G_INSTANCES[instance] = string.lower(impl) .. "_" .. string.char(G_IMPLEMENTATIONS[impl] + 64)
      else
        -- Problem, the interface name is not known...??
        G_INSTANCES[instance] = ""
      end
    end

    if label == LABEL_INVOKE then
      -- Find then method and it text name
      local method = payload_buffer(8, 1):uint()

      local param_buffer = nil
      if payload_size > 9 then
        param_buffer = payload_buffer(9, payload_size - 9)
      end

      local signature = method_signature(interface, method)
      local method_name, params = method_params(signature, param_buffer)
      local params_text = ""

      subtree:add(f_instance, payload_buffer(0,4))
      subtree:add(f_instance_tag, payload_buffer(0,4), G_INSTANCES[instance]):set_generated(true)
      subtree:add(f_interface, payload_buffer(4,4))
      subtree:add(f_method_text, payload_buffer(8,1), method_name):append_text(" (" .. tostring(method) .. ")")

      for _, param in pairs(params) do
        subtree:add(f_parameters, payload_buffer(9 + param.offset, param.size), "(" .. TypeInfo[param.typeid].text .. ") " .. param.value)
        params_text = params_text .. multiline_text(param.value) .. ", "
      end

      params_text = string.sub(params_text, 1, -3)

      -- Construct the call line and cache it so it can be used with the return call
      local call_line = string.format("%s->%s(%s)", G_INSTANCES[instance], method_name, params_text)
      pinfo.cols.info = call_line .. " called"
      G_CALL_LINES[frame] = call_line
      G_SIGNATURES[frame] = signature

      -- Done with the invoke message, advance...
      offset = (offset + (2 * 4) + 1)

    elseif label == LABEL_ANNOUNCE then
      -- Beware, the announce data is in little endian!

      if G_PROCESSES[source_id] == nil then
        -- Construct process name
        local process_id = payload_buffer(0,4):le_uint()
        G_PROCESSES[source_id] = string.format("WPEProcess[%u]", process_id)
      end

      subtree:add_le(f_process_id, payload_buffer(0,4))
      subtree:add_le(f_instance, payload_buffer(4,4))
      subtree:add(f_instance_tag, payload_buffer(0,4), G_INSTANCES[instance]):set_generated(true)
      subtree:add_le(f_interface, payload_buffer(8,4))
      subtree:add_le(f_exchange_id, payload_buffer(12,4))
      subtree:add_le(f_version, payload_buffer(16,4))

      -- Fill in kind or class name
      if payload_buffer(20, 1):uint() == 0 then
        subtree:add(f_kind, payload_buffer(21,1))
      else
        subtree:add(f_class, payload_buffer(20,64))
      end

      pinfo.cols.info = string.format("%s instance 0x%08x '%s' announced", INTERFACES[interface], instance, G_INSTANCES[instance])

      -- Done with the announce message, advance...
      offset = (offset + (5 * 4) + 64)
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

    local duration = string.format("%.6f", (pinfo.rel_ts - G_TIMESTAMPS[G_REQUESTS[frame]])):gsub(",",".")

    -- We always know the request frame
    subtree:add(f_frame_request, payload_buffer(0,0), G_REQUESTS[frame]):set_text("This is a response to the COM-RPC call in frame: " .. G_REQUESTS[frame]):set_generated(true)
    subtree:add(f_call_duration, payload_buffer(0,0), duration):set_text(string.format("Time elapsed since invoke: %s seconds", duration)):set_generated(true)

    if label == LABEL_INVOKE then
      -- Use the cached call line to fill it in here
      local return_value_buffer = nil
      if payload_size > 0 then
        return_value_buffer = payload_buffer(0, payload_size)
      end

      local name, params = method_return_value(G_SIGNATURES[G_REQUESTS[frame]], return_value_buffer)
      local params_text = ""

      for _, param in pairs(params) do
        subtree:add(f_return_value, payload_buffer(param.offset, param.size), "(" .. TypeInfo[param.typeid].text .. ") " .. param.value)
        params_text = params_text .. multiline_text(param.value) .. ", "
      end

      params_text = string.sub(params_text, 1, -3)

      pinfo.cols.info = G_CALL_LINES[G_REQUESTS[frame]] .. " returned " .. params_text

    elseif label == LABEL_ANNOUNCE then
      -- Fill in sequence number
      subtree:add(f_sequence, payload_buffer(4,4))

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
    end
  end

  -- Raw parameters data
  if label == LABEL_INVOKE then
    if buffer_length - offset > 0 then
      local data_tree = subtree:add(f_data, buffer(offset, buffer_length - offset))
    else
      subtree:add(f_no_data, buffer(0,0)):set_text("No data"):set_generated(true)
    end
  end
end


local thunder_over_tcp = DissectorTable.get("tcp.port")
thunder_over_tcp:add(THUNDER_COM_PORT, thunder_protocol_tcp)
