package probe

import (
	"testing"
	"time"
)

func TestParseWindowsTracert(t *testing.T) {
	for _, tc := range []struct {
		line, ip string
		loss     float64
		rtt      time.Duration
	}{
		{" 1 <1 ms 1 ms 2 ms 192.168.1.1", "192.168.1.1", 0, 500 * time.Microsecond},
		{" 2 10 ms * 12 ms 10.0.0.1", "10.0.0.1", 100.0 / 3, 10 * time.Millisecond},
		{" 3 * * * 请求超时。", "*", 100, 0},
		{" 4 1 毫秒 2 毫秒 3 毫秒 2001:db8::1", "2001:db8::1", 0, time.Millisecond},
	} {
		h, ok := parseTracerouteLine(tc.line)
		if !ok || h.IP != tc.ip || h.Loss != tc.loss || h.RTT1 != tc.rtt {
			t.Errorf("%q: got %+v (ok=%t)", tc.line, h, ok)
		}
	}
}
