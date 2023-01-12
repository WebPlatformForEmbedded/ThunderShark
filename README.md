# ThunderShark
Wireshark plugin for analyzing COM-RPC calls going over the wire.

The .lua file need to be placed in Wireshark's "plugins" folder
together with the generated .data file (in Windows this is normally
%APPDATA%\Wireshark\plugins or %APPDATA%\Roaming\Wireshark\plugins
and on Linux ~/.local/lib/wireshark/plugins).

Once the plugin is installed Wireshark will automatically dissect COM-RPC
frames of the captured pcap data. Typically you will want to filter
by "thunder-comrpc" protocol.

Note that version 4.0 (or greater) of Wireshark is required.

# Example capture

Use ```./GenerateLua.sh``` to create ```protocol-thunder-comrpc.data``` and place it
together with ```protocol-thunder-comrpc.lua``` in Wireshark plugins directory.

Configure Thunder to use TCP/IP port 62000 for COM-RPC communication.

On the DUT execute
```tcpdump -i lo port 62000 -w /tmp/comrpc-traffic-dump.pcap```

Start WPEFramework.

Load the .pcap file into Wireshark, dive deep.