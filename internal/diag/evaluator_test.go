package diag

import (
	"errors"
	"strings"
	"testing"
	"time"

	"routeScan/internal/probe"
)

func TestEvaluateWifiBottleneck(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("Gateway", "http://192.168.31.1", "192.168.31.1"),
		TCP:    25 * time.Millisecond,
		Jitter: 12 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{GatewayIP: "192.168.31.1"}
	res := Evaluate(snap, env)

	if res.Level != LevelWarning {
		t.Errorf("expected level WARNING, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "本地局域网/Wi-Fi") {
		t.Fatalf("expected Wi-Fi bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateWifiOptimal(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target:     probe.NewTarget("本地网关", "http://192.168.1.1", "192.168.1.1"),
		TCP:        2 * time.Millisecond,
		Jitter:     1 * time.Millisecond,
		PacketLoss: 0.0,
	}
	env := &probe.EnvironmentInfo{GatewayIP: "192.168.1.1"}
	res := Evaluate(snap, env)

	if res.Level != LevelOptimal {
		t.Errorf("expected level OPTIMAL, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "无瓶颈") {
		t.Fatalf("expected no bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateDNSBottleneck(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("OpenAI", "https://api.openai.com", "api.openai.com:443"),
		DNS:    150 * time.Millisecond,
		TCP:    30 * time.Millisecond,
		TLS:    40 * time.Millisecond,
		TTFB:   500 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{ProxyEnabled: true}
	res := Evaluate(snap, env)

	if res.Level != LevelWarning {
		t.Errorf("expected level WARNING, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "本地 DNS") {
		t.Fatalf("expected DNS bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateCrossOceanBGPDetour(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("OpenAI", "https://api.openai.com", "api.openai.com:443"),
		DNS:    15 * time.Millisecond,
		TCP:    280 * time.Millisecond, // > MaxUSTCPRTT (180ms)
		TLS:    120 * time.Millisecond,
		TTFB:   800 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{ProxyEnabled: true}
	res := Evaluate(snap, env)

	if res.Level != LevelWarning {
		t.Errorf("expected level WARNING, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "BGP 路由绕路") && !strings.Contains(res.Bottleneck, "海缆") {
		t.Fatalf("expected cross-ocean / BGP detour bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateServerQueueBottleneck(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		DNS:    12 * time.Millisecond,
		TCP:    42 * time.Millisecond,
		TLS:    38 * time.Millisecond,
		TTFB:   3200 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{ProxyEnabled: true}
	res := Evaluate(snap, env)

	if res.Level != LevelNormal {
		t.Errorf("expected level NORMAL for server queue, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "官方服务端/模型推理") {
		t.Fatalf("expected server queue bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateOptimalLink(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		DNS:    10 * time.Millisecond,
		TCP:    50 * time.Millisecond,
		TLS:    40 * time.Millisecond,
		TTFB:   400 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{ProxyEnabled: true}
	res := Evaluate(snap, env)

	if res.Level != LevelOptimal {
		t.Errorf("expected level OPTIMAL, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "全链路正常无卡顿") {
		t.Fatalf("expected all optimal bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateConnectionFailure(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		Err:    errors.New("dial tcp i/o timeout"),
	}
	env := &probe.EnvironmentInfo{}
	res := Evaluate(snap, env)

	if res.Level != LevelError {
		t.Errorf("expected level CRITICAL, got %v", res.Level)
	}
	if !strings.Contains(res.Bottleneck, "网络不通或端口受阻") {
		t.Fatalf("expected network blocked bottleneck, got %s", res.Bottleneck)
	}
}

func TestEvaluateNilSnapshot(t *testing.T) {
	res := Evaluate(nil, nil)
	if res.Level != LevelNormal {
		t.Errorf("expected level NORMAL, got %v", res.Level)
	}
	if !strings.Contains(res.StatusDesc, "等待探测数据") {
		t.Fatalf("expected waiting status desc, got %s", res.StatusDesc)
	}
}
