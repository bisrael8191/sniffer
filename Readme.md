Sniffer
======
Go version of a raw socket packet sniffer. Uses the [gopacket](https://github.com/google/gopacket) 
library with inspiration from the [PacketBeat](https://github.com/packetbeat/packetbeat) project.

# Configure
* Install build tools: `apt-get install build-essential`
* Install libpcap: `apt-get install libpcap-dev`
* Download dependencies: `go get`
* *Optional:* Modify the config.ini values

# Build
* Build the executable: `go build`

# Help
```
$ ./sniffer -h
Usage of ./sniffer:
  -config="": Path to ini config for using in go flags. May be relative to the current executable path.
  -enableAf=false: Enable afpacket mode
  -iface="eth0": Interface to capture packets
  -pcapOut="": File path to log all packets
```

# Run
* Without PCAP logging: `./rawsocket`
* With PCAP logging: `./rawsocket -pcapOut="output.pcap"
* Use config file: `./rawsocket -config="config.ini"

# Clean
`go clean` 
