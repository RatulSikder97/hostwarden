package host

import (
	"math"
	"net/netip"
	"testing"
)

func TestParseHexAddrPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"0100007F:1F90", "127.0.0.1:8080", false},
		{"00000000:18EB", "0.0.0.0:6379", false},
		{"076433C6:0D05", "198.51.100.7:3333", false},
		{"00000000000000000000000000000000:0947", "[::]:2375", false},
		{"00000000000000000000000001000000:0016", "[::1]:22", false},
		{"0000000000000000FFFF00000100007F:18EB", "127.0.0.1:6379", false},
		{"B80D0120000000000000000000000001:01BB", "[2001:db8::100:0]:443", false},
		{"zz:00", "", true},
		{"0100007F", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseHexAddrPort(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got.String() != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestSocketListening(t *testing.T) {
	t.Parallel()
	ap := netip.MustParseAddrPort
	tests := []struct {
		s    Socket
		want bool
	}{
		{Socket{Proto: "tcp", State: StateListen}, true},
		{Socket{Proto: "tcp", State: StateEstablished}, false},
		{Socket{Proto: "udp", State: StateUnconnected, Remote: ap("0.0.0.0:0")}, true},
		{Socket{Proto: "udp6", State: StateUnconnected, Remote: ap("[::]:0")}, true},
		{Socket{Proto: "udp", State: StateEstablished, Remote: ap("192.0.2.1:53")}, false},
	}
	for _, tc := range tests {
		if got := tc.s.Listening(); got != tc.want {
			t.Errorf("%+v Listening() = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestParseStat(t *testing.T) {
	t.Parallel()
	// comm containing spaces and parentheses must not shift fields.
	s := "4242 (evil) (x) R 1 4242 4242 0 -1 4194560 1 0 0 0 5000 5000 0 0 20 0 1 0 10000 1 1\n"
	ppid, cpu := parseStat(s, 200)
	if ppid != 1 {
		t.Errorf("ppid = %d, want 1", ppid)
	}
	// 100s of CPU over (200 - 100)s elapsed = 100%.
	if math.Abs(cpu-100) > 0.01 {
		t.Errorf("cpu = %.2f, want 100", cpu)
	}
	if _, cpu := parseStat("garbage", 10); cpu != 0 {
		t.Errorf("garbage cpu = %v", cpu)
	}
}

func TestUnescapeMount(t *testing.T) {
	t.Parallel()
	if got := unescapeMount(`/mnt/my\040disk`); got != "/mnt/my disk" {
		t.Errorf("got %q", got)
	}
}
