package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func getIFaceNameDarwin() ([]string, error) {
	var ifaceNames []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ifaceNames, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		if len(iface.Name) >= 2 && iface.Name[:2] == "en" {
			ifaceNames = append(ifaceNames, iface.Name)
		}
	}

	if len(ifaceNames) == 0 {
		return ifaceNames, fmt.Errorf("No suitable network interface found")
	}
	return ifaceNames, nil
}

func getIPAddrFrom(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	var ipOfIFace *net.IPNet
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok {
			maskLen := len(ip.Mask)

			if ipv4 := ip.IP.To4(); ipv4 != nil {
				ipOfIFace = &net.IPNet{
					IP:   ipv4,
					Mask: ip.Mask[maskLen-4:],
				}
				break
			} else {
				ipv4 = ip.IP.To16()
				if ipv4 == nil {
					continue
				}
				ipOfIFace = &net.IPNet{
					IP:   ipv4,
					Mask: ip.Mask[maskLen-4:],
				}
				break
			}
		}
	}

	return ipOfIFace, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range ifaces {
		assignedIP, err := getIPAddrFrom(&iface)
		if err != nil {
			log.Fatal(err)
		}
		if assignedIP == nil {
			continue
		}
		log.Println(*assignedIP)
	}

	ifaceNames, err := getIFaceNameDarwin()
	if err != nil {
		log.Fatal(err)
	}
	_snapshotLen := int32(1024)
	_promiscuous := false
	_timeout := 1000 * time.Millisecond
	canBindToDev := false
	for _, ifaceName := range ifaceNames {
		if canBindToDev {
			break
		}

		handle, err := pcap.OpenLive(ifaceName, _snapshotLen, _promiscuous, _timeout)
		if err != nil || handle == nil {
			log.Println(err)
			continue
		}
		defer handle.Close()

		_filter := "tcp src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"
		if err := handle.SetBPFFilter(_filter); err != nil {
			log.Println(err)
			continue
		}
		canBindToDev = true

		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		var cnt int
		fmt.Println("Starting capture on", ifaceName)
		for packet := range packetSrc.Packets() {
			cnt++
			fmt.Printf("Packet[%d]: %s\n", cnt, packet.String())
		}
	}
}
