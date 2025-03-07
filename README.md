# ThunderShark
Wireshark plugin for analyzing COM-RPC calls going over the wire.

The .lua file need to be placed in Wireshark's "plugins" folder
together with the generated .data file (in Windows this is normally
%APPDATA%\Wireshark\plugins or %APPDATA%\Roaming\Wireshark\plugins
and on Linux ~/.local/lib/wireshark/plugins).

Once the plugin is installed Wireshark will automatically dissect COM-RPC
frames of the captured pcap data. Typically you will want to filter
by "thunder-comrpc" protocol or a specific process (shortcuts are
available in Tools/ThunderShark menu).

Note that version 4.0 (or greater) of Wireshark is required.

# Configuration

COM-RPC protocol settings are available under Edit/Preferences/Protocols/Thunder, and, they need to be adjusted for data parsing to work properly.

The plugin monitors the TCP port for data exchange and identifies data as COM-RPC payload based on the port number.

The Instance ID is NOT platform agnostic and it should be set to 8, 16, 32 or 64, for a 8-bit, 16-bit, 32-bit or 64-bit host system respectively.

# Example capture

Use ```./GenerateLua.sh``` to create ```protocol-thunder-comrpc.data``` and place it
together with ```protocol-thunder-comrpc.lua``` in the Wireshark plugins directory.

Configure Thunder to use a TCP/IP socket COM-RPC communication (e.g. port 62000). You
can also capture other COM servers (like OpenCDM) simultaneously.

On the DUT execute
```tcpdump -i lo port 62000 -w /tmp/comrpc-traffic-dump.pcap```

(Or use any other tool able to capture TCP/IP traffic and save it to a pcap file.)

Start WPEFramework.

Load the .pcap file into Wireshark, dive deep.
