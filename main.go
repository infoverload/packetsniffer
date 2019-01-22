package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Confirm device information.
	handle, err := pcap.OpenLive("eth1", 200, false, time.Second*2)
	if err != nil {
		log.Fatalf("device eth1 not cannot be opened: %v", err)
	}

	// Note: link type refers refers to the type of packets to decode (i.e. link layer).
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	for p := range ps.Packets() {
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp := tcpLayer.(*layers.TCP)

		if tcp.DstPort == 2200 {
			fmt.Println("EVIL HACKER SSH'ING!")
		}
	}
}
