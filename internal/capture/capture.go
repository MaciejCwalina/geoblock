// Package capture reads IPv4 packets from a network interface with libpcap.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// snapshotLength only needs to cover link and IPv4 headers; the wire length
// is taken from the capture metadata.
const snapshotLength = 128

// readTimeout bounds how long a read blocks, so cancellation is noticed.
const readTimeout = 500 * time.Millisecond

// HandlerFunc receives the addresses and on-wire length of each packet.
type HandlerFunc func(source, destination netip.Addr, size int)

// Run captures on interfaceName with the given BPF filter, calling handler for
// every IPv4 packet until ctx is cancelled. The pcap handle is closed before
// Run returns.
func Run(ctx context.Context, interfaceName, filter string, handler HandlerFunc) error {
	captureHandle, err := pcap.OpenLive(interfaceName, snapshotLength, false, readTimeout)
	if err != nil {
		return fmt.Errorf("open %s: %w", interfaceName, err)
	}
	defer captureHandle.Close()

	if err := captureHandle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("set BPF filter %q: %w", filter, err)
	}

	var (
		ethernet layers.Ethernet
		linuxSLL layers.LinuxSLL
		ipv4     layers.IPv4
		decoded  = make([]gopacket.LayerType, 0, 4)
	)
	var firstLayer gopacket.LayerType
	switch captureHandle.LinkType() {
	case layers.LinkTypeEthernet:
		firstLayer = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		firstLayer = layers.LayerTypeLinuxSLL
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		firstLayer = layers.LayerTypeIPv4
	default:
		return fmt.Errorf("unsupported link type %s on %s", captureHandle.LinkType(), interfaceName)
	}
	parser := gopacket.NewDecodingLayerParser(firstLayer, &ethernet, &linuxSLL, &ipv4)
	// Transport layers are not decoded; stop quietly at the IPv4 payload.
	parser.IgnoreUnsupported = true

	for ctx.Err() == nil {
		data, captureInfo, err := captureHandle.ZeroCopyReadPacketData()
		switch {
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return fmt.Errorf("read packet: %w", err)
		}

		if err := parser.DecodeLayers(data, &decoded); err != nil {
			continue
		}
		for _, layerType := range decoded {
			if layerType != layers.LayerTypeIPv4 {
				continue
			}
			source, sourceOK := netip.AddrFromSlice(ipv4.SrcIP)
			destination, destinationOK := netip.AddrFromSlice(ipv4.DstIP)
			if sourceOK && destinationOK {
				handler(source, destination, captureInfo.Length)
			}
		}
	}
	return nil
}
