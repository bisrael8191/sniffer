package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket/pcapgo"
	"github.com/vharitonsky/iniflags"
)

// Command line flags and documentation
var (
	iface    = flag.String("iface", "eth0", "Interface to capture packets")
	pcapOut  = flag.String("pcapOut", "", "File path to log all packets")
	enableAF = flag.Bool("enableAf", false, "Enable afpacket mode")
)

// Store useful variables and objects
type Config struct {
	iface      string
	pcapOut    string
	enableAF   bool
	pcapFile   *os.File
	pcapWriter *pcapgo.Writer
	sniffer    Sniffer
	isRunning  bool
}

func main() {
	// Parse any set command line flags
	iniflags.Parse()

	config := &Config{iface: *iface, pcapOut: *pcapOut, enableAF: *enableAF, isRunning: true}

	// On ^C or SIGTERM, gracefully stop anything running
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		log.Print("Received sigterm/sigint, stopping")
		config.isRunning = false
	}()

	// Open pcap log output
	if err := openPcap(config); err != nil {
		log.Fatal("Error opening pcap file: ", err)
	}
	defer config.pcapFile.Close()

	// Listen on the interface
	var sniffer Sniffer
	if config.enableAF {
		sniffer = &AfpacketSniffer{}
		log.Print("Using afpacket to sniff packets")
	} else {
		sniffer = &PcapSniffer{}
		log.Print("Using libpcap to sniff packets")
	}

	if err := sniffer.Open(config); err != nil {
		log.Fatal("Failed to open the sniffer: ", err)
	}
	config.sniffer = sniffer
	defer config.sniffer.Close()
	log.Printf("Listening on %s\n", config.iface)

	if err := Listen(config); err != nil {
		log.Fatal("Listening stopped with an error: ", err)
	}

	log.Print("Successful exit")
}
