package probe

import (
	"errors"
	"os/exec"
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
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("system traceroute command is not installed")
	}
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

func TestTraceHopsMissingCommandDoesNotInventHops(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	hops, count, err := TraceHops("127.0.0.1", 2)
	if err == nil || len(hops) != 0 || count != 0 {
		t.Fatalf("missing command must report no measured hops: %v, %d, %v", hops, count, err)
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

func TestBuildProxyTopology(t *testing.T) {
	geoMgr := geoip.NewManager("") // 使用内置规则
	defer geoMgr.Close()

	env := &EnvironmentInfo{
		GatewayIP:      "192.168.5.1",
		HasTUN:         true,
		ProxyEnabled:   true,
		ProxyURL:       "http://127.0.0.1:7890",
		EgressIP:       "109.61.127.58",
		EgressLocation: "韩国 仁川 (AS199524 G-Core Labs S.A.)",
	}

	snap := &ProbeSnapshot{
		Target: NewTarget("Anthropic Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		DNS:    0,
		TCP:    2 * time.Millisecond,
		TLS:    428 * time.Millisecond,
		TTFB:   726 * time.Millisecond,
	}

	// 1. 本地网关测试
	gwTarget := NewTarget("本地网关", "http://192.168.5.1", "192.168.5.1")
	gwHops := BuildProxyTopology(gwTarget, env, snap, geoMgr)
	if len(gwHops) != 1 {
		t.Fatalf("expected 1 hop for gateway, got %d", len(gwHops))
	}
	if gwHops[0].IP != "192.168.5.1" {
		t.Fatalf("expected IP 192.168.5.1, got %s", gwHops[0].IP)
	}

	// 2. 外部服务 5 跳拓扑测试 (Anthropic Claude)
	aiHops := BuildProxyTopology(snap.Target, env, snap, geoMgr)
	if len(aiHops) != 5 {
		t.Fatalf("expected 5 hops for AI service under proxy, got %d", len(aiHops))
	}

	// Hop 1: 物理网关
	if aiHops[0].HopNum != 1 || aiHops[0].IP != "192.168.5.1" {
		t.Fatalf("unexpected hop 1: %+v", aiHops[0])
	}
	// Hop 2: TUN 网卡
	if aiHops[1].HopNum != 2 || aiHops[1].IP != "198.18.0.1" {
		t.Fatalf("unexpected hop 2: %+v", aiHops[1])
	}
	// Hop 3: 境外出口
	if aiHops[2].HopNum != 3 || aiHops[2].IP != "109.61.127.58" || aiHops[2].RTT1 != 428*time.Millisecond {
		t.Fatalf("unexpected hop 3: %+v", aiHops[2])
	}
	if !strings.Contains(aiHops[2].Geo, "韩国") {
		t.Fatalf("expected 韩国 in hop 3 geo, got %s", aiHops[2].Geo)
	}
	// Hop 4: CDN Anycast
	if aiHops[3].HopNum != 4 || !strings.Contains(aiHops[3].Host, "Cloudflare") {
		t.Fatalf("unexpected hop 4: %+v", aiHops[3])
	}
	// Hop 5: 模型 API
	if aiHops[4].HopNum != 5 || aiHops[4].RTT1 != 726*time.Millisecond {
		t.Fatalf("unexpected hop 5: %+v", aiHops[4])
	}

	// 3. 非 TUN 代理模式测试
	envNoTUN := &EnvironmentInfo{
		GatewayIP:    "192.168.1.1",
		HasTUN:       false,
		ProxyEnabled: true,
		ProxyURL:     "http://127.0.0.1:7890",
		EgressIP:     "109.61.127.58",
	}
	aiHopsNoTUN := BuildProxyTopology(snap.Target, envNoTUN, snap, geoMgr)
	if len(aiHopsNoTUN) != 5 {
		t.Fatalf("expected 5 hops, got %d", len(aiHopsNoTUN))
	}
	if aiHopsNoTUN[1].IP != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1 for hop 2 in non-TUN mode, got %s", aiHopsNoTUN[1].IP)
	}
}
