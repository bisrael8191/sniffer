package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
)

// afpacket version of the gopacket library
type AfpacketSniffer struct {
	handle *afpacket.TPacket
}

// Computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size. From PacketBeat.
func afpacketComputeSize(target_size_mb int, snaplen int, page_size int) (
	frame_size int, block_size int, num_blocks int, err error) {

	if snaplen < page_size {
		frame_size = page_size / (page_size / snaplen)
	} else {
		frame_size = (snaplen/page_size + 1) * page_size
	}

	// 128 is the default from the gopacket library so just use that
	block_size = frame_size * 128
	num_blocks = (target_size_mb * 1024 * 1024) / block_size

	if num_blocks == 0 {
		return 0, 0, 0, fmt.Errorf("Buffer size too small")
	}

	return frame_size, block_size, num_blocks, nil
}

func (s *AfpacketSniffer) Open(config *Config) error {
	// Capture settings
	const (
		// MMap buffer size
		buffer_mb int = 24
		// Max packet length
		snaplen int = 65536
		// Set the interface in promiscuous mode
		promisc bool = true
	)

	frame_size, block_size, num_blocks, err := afpacketComputeSize(
		buffer_mb,
		snaplen,
		os.Getpagesize())
	if err != nil {
		return fmt.Errorf("Error calculating afpacket size: %s", err)
	}

	// Configure the afpacket ring and bind it to the interface
	var tPacket *afpacket.TPacket
	tPacket, err = afpacket.NewTPacket(
		afpacket.OptInterface(*iface),
		afpacket.OptFrameSize(frame_size),
		afpacket.OptBlockSize(block_size),
		afpacket.OptNumBlocks(num_blocks))
	if err != nil {
		fmt.Errorf("Error opening afpacket interface: %s", err)
	}
	s.handle = tPacket

	return nil
}

func (s *AfpacketSniffer) Close() {
	s.handle.Close()
}

func (s *AfpacketSniffer) ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error) {
	return s.handle.ZeroCopyReadPacketData()
}
