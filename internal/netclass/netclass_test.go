package netclass

import (
	"net/netip"
	"testing"
)

func TestIsPublic(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"172.16.5.4", false},
		{"192.168.20.119", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.251", false},
		{"239.255.255.250", false},
		{"255.255.255.255", false},
		{"0.0.0.0", false},
		{"100.64.0.1", false},
		{"192.0.2.10", false},
		{"240.0.0.1", false},
		{"::ffff:8.8.8.8", true},
		{"2001:4860:4860::8888", false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := IsPublic(netip.MustParseAddr(test.address)); got != test.want {
				t.Errorf("IsPublic(%s) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	classifier := NewClassifier([]netip.Addr{
		netip.MustParseAddr("203.0.114.10"), // public address owned by this host
		netip.MustParseAddr("192.168.1.10"),
	})

	tests := []struct {
		name          string
		source        string
		destination   string
		wantOK        bool
		wantRemote    string
		wantDirection Direction
	}{
		{"outbound from local public address", "203.0.114.10", "8.8.8.8", true, "8.8.8.8", Outbound},
		{"inbound to local public address", "1.1.1.1", "203.0.114.10", true, "1.1.1.1", Inbound},
		{"outbound from local private address", "192.168.1.10", "1.1.1.1", true, "1.1.1.1", Outbound},
		{"unsolicited inbound to local private address", "1.1.1.1", "192.168.1.10", true, "1.1.1.1", Inbound},
		{"outbound from unknown private address", "10.0.0.7", "8.8.8.8", true, "8.8.8.8", Outbound},
		{"inbound to unknown private address", "8.8.8.8", "10.0.0.7", true, "8.8.8.8", Inbound},
		{"local to private peer", "192.168.1.10", "192.168.1.1", false, "", ""},
		{"local to multicast", "192.168.1.10", "224.0.0.251", false, "", ""},
		{"local to broadcast", "192.168.1.10", "255.255.255.255", false, "", ""},
		{"loopback", "127.0.0.1", "127.0.0.1", false, "", ""},
		{"dhcp discover", "0.0.0.0", "255.255.255.255", false, "", ""},
		{"link local peer", "169.254.10.1", "192.168.1.10", false, "", ""},
		{"forwarded public to public", "1.1.1.1", "8.8.8.8", false, "", ""},
		{"private to private", "10.0.0.1", "10.0.0.2", false, "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flow, ok := classifier.Classify(netip.MustParseAddr(test.source), netip.MustParseAddr(test.destination))
			if ok != test.wantOK {
				t.Fatalf("ok = %v, want %v (flow %+v)", ok, test.wantOK, flow)
			}
			if !ok {
				return
			}
			if flow.Remote != netip.MustParseAddr(test.wantRemote) || flow.Direction != test.wantDirection {
				t.Errorf("flow = %+v, want remote %s direction %s", flow, test.wantRemote, test.wantDirection)
			}
		})
	}
}
