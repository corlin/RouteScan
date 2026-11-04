package tui

import (
	"os"
	"routeScan/internal/probe"
	"strings"
	"testing"
	"time"
)

func TestRenderTableFormat(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target:     probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		DNS:        12 * time.Millisecond,
		TCP:        45 * time.Millisecond,
		TLS:        38 * time.Millisecond,
		TTFB:       1120 * time.Millisecond,
		Hops:       14,
		PacketLoss: 0.0,
		Jitter:     2 * time.Millisecond,
		Timestamp:  time.Now(),
	}

	row := formatTableRow(snap, true)
	if !strings.Contains(row, "Claude") || !strings.Contains(row, "45ms") {
		t.Fatalf("unexpected formatted row: %s", row)
	}
	if !strings.HasPrefix(row, "> ") {
		t.Fatalf("expected selected cursor '> ', got: %s", row)
	}

	unselectedRow := formatTableRow(snap, false)
	if !strings.HasPrefix(unselectedRow, "  ") {
		t.Fatalf("expected unselected prefix '  ', got: %s", unselectedRow)
	}

	nilRow := formatTableRow(nil, false)
	if !strings.Contains(nilRow, "等待初次采样") {
		t.Fatalf("expected nil snapshot warning, got: %s", nilRow)
	}

	// Error snapshot
	errSnap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("GPT", "https://api.openai.com", "api.openai.com:443"),
		Err:    os.ErrNotExist,
	}
	errRow := formatTableRow(errSnap, false)
	if !strings.Contains(errRow, "CRITICAL") {
		t.Fatalf("expected CRITICAL status for err snapshot, got: %s", errRow)
	}
}

func TestRenderDashboard(t *testing.T) {
	targets := []probe.Target{
		probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		probe.NewTarget("GPT", "https://api.openai.com", "api.openai.com:443"),
	}
	state := probe.NewStateManager()
	state.Update("Claude", &probe.ProbeSnapshot{
		Target: targets[0],
		DNS:    10 * time.Millisecond,
		TCP:    25 * time.Millisecond,
		TLS:    30 * time.Millisecond,
		TTFB:   500 * time.Millisecond,
		Hops:   12,
		HopsList: []probe.HopInfo{
			{HopNum: 1, IP: "192.168.1.1", Host: "gateway.local.domain", Geo: "局域网 [本地局域网]", RTT1: time.Millisecond, RTT2: 2 * time.Millisecond, Loss: 0},
			{HopNum: 2, IP: "202.96.209.133", Host: "dns.sh.cn", Geo: "", RTT1: 5 * time.Millisecond, RTT2: 6 * time.Millisecond, Loss: 0},
		},
		Timestamp: time.Now(),
	})

	env := &probe.EnvironmentInfo{
		GatewayIP:    "192.168.1.1",
		HasTUN:       false,
		ProxyEnabled: true,
		ProxyURL:     "http://127.0.0.1:7890",
	}

	output := RenderDashboard(targets, state, 0, env, false)
	if !strings.Contains(output, "RouteScan v1.0") {
		t.Fatalf("expected header title in dashboard output: %s", output)
	}
	if !strings.Contains(output, "Claude") {
		t.Fatalf("expected target name in dashboard output: %s", output)
	}
	if !strings.Contains(output, "代理模式") {
		t.Fatalf("expected proxy mode in dashboard output: %s", output)
	}
	if !strings.Contains(output, "地理位置 & 运营商/AS") {
		t.Fatalf("expected geo column header in dashboard output: %s", output)
	}
	if !strings.Contains(output, "局域网 [本地局域网]") {
		t.Fatalf("expected geo value in dashboard output: %s", output)
	}
	if !strings.Contains(output, "dns.sh.cn") {
		t.Fatalf("expected fallback host in dashboard output: %s", output)
	}

	// Direct mode check
	directOutput := RenderDashboard(targets, state, 0, env, true)
	if !strings.Contains(directOutput, "直连模式") {
		t.Fatalf("expected direct mode in dashboard output: %s", directOutput)
	}

	// Dashboard object method check
	dash := NewDashboard(targets, state, env)
	dash.SelectedIdx = 1
	dash.IsDirect = true
	dashOut := dash.Render()
	if !strings.Contains(dashOut, "GPT") {
		t.Fatalf("expected GPT in dashboard render: %s", dashOut)
	}

	// Convenience wrapper check
	wrapOut := Render(targets, state, 0, nil, true)
	if !strings.Contains(wrapOut, "RouteScan v1.0") {
		t.Fatalf("expected RouteScan in wrapper output: %s", wrapOut)
	}
}

func TestFormatDuration(t *testing.T) {
	if s := formatDuration(0); s != "-" {
		t.Fatalf("expected '-' for 0, got %s", s)
	}
	if s := formatDuration(-5 * time.Millisecond); s != "-" {
		t.Fatalf("expected '-' for negative, got %s", s)
	}
	if s := formatDuration(450 * time.Microsecond); s != "450µs" {
		t.Fatalf("expected '450µs', got %s", s)
	}
	if s := formatDuration(45 * time.Millisecond); s != "45ms" {
		t.Fatalf("expected '45ms', got %s", s)
	}
}

func TestTruncate(t *testing.T) {
	if s := truncate("short", 10); s != "short" {
		t.Fatalf("expected 'short', got %s", s)
	}
	if s := truncate("this is a long host string that exceeds", 10); s != "this is..." {
		t.Fatalf("expected 'this is...', got %s", s)
	}
	if s := truncate("abc", 2); s != "ab" {
		t.Fatalf("expected 'ab', got %s", s)
	}
	if s := truncate("中国上海电信骨干网核心路由节点出口", 10); s != "中国上海电信骨..." {
		t.Fatalf("expected '中国上海电信骨...', got %s", s)
	}
}

func TestScreenFunctions(t *testing.T) {
	// Screen escape functions should not panic
	EnterAltScreen()
	ClearScreen()
	ExitAltScreen()
	RestoreTerminal()
}

func TestParseKey(t *testing.T) {
	tests := []struct {
		buf  []byte
		n    int
		want KeyType
	}{
		{buf: []byte{'q'}, n: 1, want: KeyQuit},
		{buf: []byte{'Q'}, n: 1, want: KeyQuit},
		{buf: []byte{3}, n: 1, want: KeyQuit}, // Ctrl+C
		{buf: []byte{'p'}, n: 1, want: KeyProxyToggle},
		{buf: []byte{'P'}, n: 1, want: KeyProxyToggle},
		{buf: []byte{'r'}, n: 1, want: KeyRefresh},
		{buf: []byte{'R'}, n: 1, want: KeyRefresh},
		{buf: []byte{'s'}, n: 1, want: KeySnapshot},
		{buf: []byte{'S'}, n: 1, want: KeySnapshot},
		{buf: []byte{'j'}, n: 1, want: KeyDown},
		{buf: []byte{'J'}, n: 1, want: KeyDown},
		{buf: []byte{'k'}, n: 1, want: KeyUp},
		{buf: []byte{'K'}, n: 1, want: KeyUp},
		{buf: []byte{27, 91, 'A'}, n: 3, want: KeyUp},   // \033[A
		{buf: []byte{27, 91, 'B'}, n: 3, want: KeyDown}, // \033[B
		{buf: []byte{27, 79, 'A'}, n: 3, want: KeyUp},   // \033OA
		{buf: []byte{27, 79, 'B'}, n: 3, want: KeyDown}, // \033OB
		{buf: []byte{'x'}, n: 1, want: KeyNone},
		{buf: []byte{27, 91, 'C'}, n: 3, want: KeyNone},
	}

	for _, tc := range tests {
		got := parseKey(tc.buf, tc.n)
		if got != tc.want {
			t.Errorf("parseKey(%v, %d) = %v; want %v", tc.buf, tc.n, got, tc.want)
		}
	}
}

func TestExportSnapshot(t *testing.T) {
	targets := []probe.Target{
		probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		probe.NewTarget("ErrorService", "https://error.example.com", "error.example.com:443"),
	}
	state := probe.NewStateManager()
	state.Update("Claude", &probe.ProbeSnapshot{
		Target:     targets[0],
		DNS:        12 * time.Millisecond,
		TCP:        45 * time.Millisecond,
		TLS:        38 * time.Millisecond,
		TTFB:       1120 * time.Millisecond,
		Hops:       14,
		PacketLoss: 0.0,
		HopsList: []probe.HopInfo{
			{HopNum: 1, IP: "192.168.1.1", Host: "gateway.local", Geo: "局域网 [本地局域网]", RTT1: time.Millisecond, RTT2: 2 * time.Millisecond, Loss: 0},
			{HopNum: 2, IP: "202.96.209.133", Host: "dns.sh.cn", Geo: "中国 上海 电信 [AS4812]", RTT1: 5 * time.Millisecond, RTT2: 6 * time.Millisecond, Loss: 0},
		},
		Timestamp: time.Now(),
	})
	state.Update("ErrorService", &probe.ProbeSnapshot{
		Target:    targets[1],
		Err:       os.ErrPermission,
		Timestamp: time.Now(),
	})

	env := &probe.EnvironmentInfo{
		GatewayIP:    "192.168.1.1",
		ProxyEnabled: false,
	}

	tmpFile := "test_snapshot.md"
	defer os.Remove(tmpFile)

	err := ExportSnapshot(tmpFile, targets, state, env)
	if err != nil {
		t.Fatalf("ExportSnapshot failed: %v", err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read snapshot file: %v", err)
	}

	text := string(content)
	if !strings.Contains(text, "# RouteScan 网络与 AI 服务延迟体检报告") {
		t.Fatalf("missing title in snapshot: %s", text)
	}
	if !strings.Contains(text, "Claude") || !strings.Contains(text, "14") {
		t.Fatalf("missing target stats in snapshot: %s", text)
	}
	if !strings.Contains(text, "ErrorService") {
		t.Fatalf("missing error service in snapshot: %s", text)
	}
	if !strings.Contains(text, "地理位置 & 运营商/AS") {
		t.Fatalf("missing hop geo header in snapshot: %s", text)
	}
	if !strings.Contains(text, "局域网 [本地局域网]") || !strings.Contains(text, "中国 上海 电信 [AS4812]") {
		t.Fatalf("missing hop geo info in snapshot: %s", text)
	}
}
