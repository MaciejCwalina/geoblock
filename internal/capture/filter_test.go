package capture

import (
	"net/netip"
	"testing"
)

func TestBuildFilter(t *testing.T) {
	tests := []struct {
		name     string
		excluded []Endpoint
		want     string
	}{
		{
			name: "no endpoints",
			want: "ip and not net 127.0.0.0/8",
		},
		{
			name: "redis and api, duplicates and IPv6 skipped",
			excluded: []Endpoint{
				{netip.MustParseAddr("172.18.0.2"), 6379},
				{netip.MustParseAddr("208.95.112.1"), 80},
				{netip.MustParseAddr("172.18.0.2"), 6379},
				{netip.MustParseAddr("2001:db8::1"), 80},
			},
			want: "ip and not net 127.0.0.0/8 and not (host 172.18.0.2 and port 6379) and not (host 208.95.112.1 and port 80)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := BuildFilter(test.excluded); got != test.want {
				t.Errorf("BuildFilter() =\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}
