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

METHODS = {}
INTERFACES = {}

INSTANCE_ID_SIZE = 4 -- in bytes

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
  INSTANCE = 11,
  INTERFACE = 12 -- for QueryInterface() only
}

TypeInfo = {
  [Type.STRING] =     { size=0, text="string" },
  [Type.CHAR] =       { size=1, text="char" },
  [Type.INT8] =       { size=1, text="int8_t", signed=true },
  [Type.UINT8] =      { size=1, text="uint8_t", signed=false },
  [Type.INT16] =      { size=2, text="int16_t", signed=true },
  [Type.UINT16] =     { size=2, text="uint16_t", signed=false },
  [Type.INT32] =      { size=4, text="int32_t", signed=true },
  [Type.UINT32] =     { size=4, text="uint32_t", signed=false },
  [Type.INT64] =      { size=8, text="int64_t", signed=true },
  [Type.UINT64] =     { size=8, text="uint64_t", signed=false },
  [Type.STRING] =     { size=0, text="string" },
  [Type.INSTANCE] =   { size=INSTANCE_ID_SIZE, text="instance_id" },
  [Type.INTERFACE] =  { size=4, text="interface_id" }
}
