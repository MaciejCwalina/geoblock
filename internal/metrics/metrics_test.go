package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObservePacket(t *testing.T) {
	collectors := New(prometheus.NewRegistry())
	collectors.ObservePacket("in", "CN", 100)
	collectors.ObservePacket("in", "CN", 50)
	collectors.ObservePacket("out", "", 10)

	tests := []struct {
		direction, country string
		wantPackets        float64
		wantBytes          float64
	}{
		{"in", "CN", 2, 150},
		{"out", UnknownCountry, 1, 10},
	}
	for _, test := range tests {
		if got := testutil.ToFloat64(collectors.Packets.WithLabelValues(test.direction, test.country)); got != test.wantPackets {
			t.Errorf("packets{%s,%s} = %v, want %v", test.direction, test.country, got, test.wantPackets)
		}
		if got := testutil.ToFloat64(collectors.Bytes.WithLabelValues(test.direction, test.country)); got != test.wantBytes {
			t.Errorf("bytes{%s,%s} = %v, want %v", test.direction, test.country, got, test.wantBytes)
		}
	}
	if series := testutil.CollectAndCount(collectors.Packets); series != 2 {
		t.Errorf("packet series = %d, want 2", series)
	}
}
