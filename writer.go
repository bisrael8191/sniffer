package main

import (
	"log"
	"os"

	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcapgo"
)

// Open and create a pcap output file
func openPcap(config *Config) error {
	if config.pcapOut != "" {
		f, err := os.Create(config.pcapOut)
		w := pcapgo.NewWriter(f)

		// Write the PCAP global header
		w.WriteFileHeader(65536, layers.LinkTypeEthernet)

		// Store the file/writer handles
		config.pcapFile = f
		config.pcapWriter = w
		log.Printf("Logging packets to %s", config.pcapOut)

		return err
	}

	return nil
}
