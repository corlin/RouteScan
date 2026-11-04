package probe

import (
	"strings"
	"testing"
	"time"

	"routeScan/internal/geoip"
)

func TestParseTracerouteLine(t *testing.T) {
	line := " 1  192.168.31.1 (192.168.31.1)  0.785 ms  0.642 ms  0.710 ms"
	hop, ok := parseTracerouteLine(line)
	if !ok {
		t.Fatalf("expected parse line success")
	}
	if hop.HopNum != 1 || hop.IP != "192.168.31.1" {
		t.Fatalf("unexpected hop info: %+v", hop)
	}
	if hop.RTT1 == 0 || hop.RTT1 > 2*time.Millisecond {
		t.Fatalf("unexpected RTT: %v", hop.RTT1)
	}
	if hop.RTT2 == 0 || hop.RTT3 == 0 {
		t.Fatalf("expected RTT2 and RTT3 populated")
	}
}

func TestParseTracerouteLineIPOnly(t *testing.T) {
	line := " 1  127.0.0.1  0.268 ms"
	hop, ok := parseTracerouteLine(line)
	if !ok {
		t.Fatalf("expected parse line success")
	}
	if hop.HopNum != 1 || hop.IP != "127.0.0.1" || hop.Host != "127.0.0.1" {
		t.Fatalf("unexpected hop info: %+v", hop)
	}
	if hop.RTT1 == 0 {
		t.Fatalf("expected positive RTT1")
	}
}

func TestParseTracerouteLineInvalid(t *testing.T) {
	invalids := []string{
		"",
		"   ",
		"traceroute to 127.0.0.1 (127.0.0.1), 2 hops max, 40 byte packets",
		"some random log",
	}
	for _, line := range invalids {
		if _, ok := parseTracerouteLine(line); ok {
			t.Fatalf("expected parse failure for line: %q", line)
		}
	}
}

func TestParseTracerouteLineTimeout(t *testing.T) {
	tests := []string{
		" 2  * * *",
		" 3  *",
	}
	for _, line := range tests {
		hop, ok := parseTracerouteLine(line)
		if !ok {
			t.Fatalf("expected parse timeout line success: %q", line)
		}
		if hop.IP != "*" || hop.Loss != 100.0 {
			t.Fatalf("unexpected timeout hop info: %+v", hop)
		}
	}
}

func TestEstimateHopsFromTTL(t *testing.T) {
	// 收到 TTL 54 -> 常见初始 64 -> 64 - 54 + 1 = 11 跳
	hops := EstimateHopsFromTTL(54)
	if hops != 11 {
		t.Fatalf("expected 11 hops, got %d", hops)
	}

	// 收到 TTL 115 -> 常见初始 128 -> 128 - 115 + 1 = 14 跳
	hops = EstimateHopsFromTTL(115)
	if hops != 14 {
		t.Fatalf("expected 14 hops, got %d", hops)
	}

	// 边界测试：<= 0 返回缺省 12
	if hops := EstimateHopsFromTTL(0); hops != 12 {
		t.Fatalf("expected 12 hops for TTL 0, got %d", hops)
	}
	if hops := EstimateHopsFromTTL(-5); hops != 12 {
		t.Fatalf("expected 12 hops for TTL -5, got %d", hops)
	}

	// 大于 128 -> 初始 255
	if hops := EstimateHopsFromTTL(240); hops != 16 {
		t.Fatalf("expected 16 hops for TTL 240, got %d", hops)
	}
}

func TestTraceHopsLocalhost(t *testing.T) {
	hops, count, err := TraceHops("127.0.0.1", 2)
	if err != nil {
		t.Fatalf("TraceHops failed: %v", err)
	}
	if count <= 0 {
		t.Fatalf("expected positive hop count, got %d", count)
	}
	if len(hops) == 0 {
		t.Logf("no hops parsed (traceroute might be restricted or formatted differently)")
	}
}

func TestTraceHopsGeoAnnotation(t *testing.T) {
	line := " 1  192.168.1.1 (192.168.1.1)  0.785 ms"
	hop, ok := parseTracerouteLine(line)
	if !ok {
		t.Fatalf("failed to parse line")
	}
	mgr := geoip.NewManager("")
	loc := mgr.Lookup(hop.IP)
	hop.Geo = loc.String()
	hop.ASN = loc.ASN
	expectedGeo := "[局域网] 本地局域网 / 家庭网关"
	if hop.Geo != expectedGeo {
		t.Fatalf("expected Geo %q, got %q", expectedGeo, hop.Geo)
	}
	if !strings.Contains(hop.Geo, "局域网") {
		t.Fatalf("expected 局域网 geo, got %s", hop.Geo)
	}

	// Also test annotateHopWithGeo
	var hopAnnotated HopInfo
	hopAnnotated, ok = parseTracerouteLine(line)
	if !ok {
		t.Fatalf("failed to parse line")
	}
	annotateHopWithGeo(&hopAnnotated, mgr)
	if hopAnnotated.Geo != expectedGeo {
		t.Fatalf("expected annotated Geo %q, got %q", expectedGeo, hopAnnotated.Geo)
	}

	// Test timeout hop does not get annotated
	timeoutHop := HopInfo{HopNum: 2, IP: "*"}
	annotateHopWithGeo(&timeoutHop, mgr)
	if timeoutHop.Geo != "" || timeoutHop.ASN != "" {
		t.Fatalf("expected empty Geo and ASN for timeout hop, got Geo=%q ASN=%q", timeoutHop.Geo, timeoutHop.ASN)
	}

	// Test nil manager does not panic
	hopNilMgr := HopInfo{HopNum: 1, IP: "192.168.1.1"}
	annotateHopWithGeo(&hopNilMgr, nil)
	if hopNilMgr.Geo != "" {
		t.Fatalf("expected empty Geo when mgr is nil, got %q", hopNilMgr.Geo)
	}
}
