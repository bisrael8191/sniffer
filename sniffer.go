package main

import (
	"log"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

type Sniffer interface {
	// Open and configure the network interface
	Open(config *Config) error

	// Close the interface
	Close()

	// Read the next packet from the interface
	ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error)
}

// Layers that we care about decoding
var (
	eth     layers.Ethernet
	ip      layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	dns     layers.DNS
	payload gopacket.Payload
)

// Listen in an infinite loop for new packets
func Listen(config *Config) error {
	// Array to store which layers were decoded
	decoded := []gopacket.LayerType{}

	// Faster, predefined layer parser that doesn't make copies of the layer slices
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&dns,
		&payload)

	// Infinite loop that reads incoming packets
	for config.isRunning {
		data, ci, err := config.sniffer.ReadPacket()
		if err != nil {
			log.Printf("Error getting packet: %v %s", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			log.Printf("Error decoding packet: %v", err)
			continue
		}
		if len(decoded) == 0 {
			log.Print("Packet contained no valid layers")
			continue
		}

		// Example of how to get data out of specific layers
		//        for _, layerType := range decoded {
		//            switch layerType {
		//                case layers.LayerTypeIPv4:
		//                    log.Printf("src: %v, dst: %v, proto: %v", ip.SrcIP, ip.DstIP, ip.Protocol)
		//            }
		//        }

		if config.pcapWriter != nil {
			config.pcapWriter.WritePacket(ci, data)
		}
	}

	return nil
}
