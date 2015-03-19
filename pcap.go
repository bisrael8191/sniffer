package main

import (
	"fmt"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
)

// libpcap version of the gopacket library
type PcapSniffer struct {
	handle *pcap.Handle
}

func (s *PcapSniffer) Open(config *Config) error {
	// Capture settings
	const (
		// Max packet length
		snaplen int32 = 65536
		// Set the interface in promiscuous mode
		promisc bool = true
		// Timeout duration
		flushAfter string = "10s"
		//BPF filter when capturing packets
		filter string = "ip"
	)

	// Open the interface
	flushDuration, err := time.ParseDuration(flushAfter)
	if err != nil {
		return fmt.Errorf("Invalid flush duration: %s", flushAfter)
	}
	handle, err := pcap.OpenLive(*iface, snaplen, promisc, flushDuration/2)
	if err != nil {
		return fmt.Errorf("Error opening pcap handle: %s", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("Error setting BPF filter: %s", err)
	}
	s.handle = handle

	return nil
}

func (s *PcapSniffer) Close() {
	s.handle.Close()
}

func (s *PcapSniffer) ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error) {
	return s.handle.ZeroCopyReadPacketData()
}
