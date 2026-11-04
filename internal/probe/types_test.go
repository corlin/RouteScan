package probe

import (
	"os"
	"testing"
	"time"
)

func TestNewTarget(t *testing.T) {
	tgt := NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443")
	if tgt.Name != "Claude" || tgt.Host != "api.anthropic.com:443" {
		t.Fatalf("unexpected target: %+v", tgt)
	}
}

func TestProbeSnapshotStats(t *testing.T) {
	snap := &ProbeSnapshot{
		Target:    NewTarget("GPT", "https://api.openai.com", "api.openai.com:443"),
		DNS:       15 * time.Millisecond,
		TCP:       45 * time.Millisecond,
		TLS:       35 * time.Millisecond,
		TTFB:      850 * time.Millisecond,
		Hops:      14,
		Timestamp: time.Now(),
	}
	if snap.TotalHandshake() != 80*time.Millisecond {
		t.Fatalf("expected TCP+TLS=80ms, got %v", snap.TotalHandshake())
	}
}

func TestStateManager(t *testing.T) {
	sm := NewStateManager()
	tgt := NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443")
	snap := &ProbeSnapshot{Target: tgt, TCP: 10 * time.Millisecond}
	sm.Update("Claude", snap)

	got := sm.Get("Claude")
	if got == nil || got.Target.Name != "Claude" {
		t.Fatalf("expected snapshot for Claude, got %+v", got)
	}

	for i := 0; i < 35; i++ {
		sm.Update("Claude", &ProbeSnapshot{Target: tgt, StatusCode: i})
	}
	if len(sm.History["Claude"]) != 30 {
		t.Fatalf("expected history length 30, got %d", len(sm.History["Claude"]))
	}
}

func TestStateManagerPacketLossAndJitter(t *testing.T) {
	sm := NewStateManager()
	tgt := NewTarget("OpenAI", "https://api.openai.com", "api.openai.com:443")

	// 1st update: TCP 50ms
	sm.Update("OpenAI", &ProbeSnapshot{Target: tgt, TCP: 50 * time.Millisecond})
	snap1 := sm.Get("OpenAI")
	if snap1.PacketLoss != 0.0 {
		t.Fatalf("expected 0%% loss, got %v", snap1.PacketLoss)
	}

	// 2nd update: TCP 70ms -> Jitter should be |70-50| = 20ms
	sm.Update("OpenAI", &ProbeSnapshot{Target: tgt, TCP: 70 * time.Millisecond})
	snap2 := sm.Get("OpenAI")
	if snap2.Jitter != 20*time.Millisecond {
		t.Fatalf("expected 20ms jitter, got %v", snap2.Jitter)
	}

	// 3rd update: Error -> PacketLoss should be 1/3 (33.3%)
	sm.Update("OpenAI", &ProbeSnapshot{Target: tgt, Err: os.ErrDeadlineExceeded})
	snap3 := sm.Get("OpenAI")
	if snap3.PacketLoss < 33.0 || snap3.PacketLoss > 34.0 {
		t.Fatalf("expected ~33.3%% loss, got %v", snap3.PacketLoss)
	}

	// Test UpdateHops & preservation
	hops := []HopInfo{
		{HopNum: 1, IP: "192.168.1.1", Host: "gw", RTT1: time.Millisecond},
	}
	sm.UpdateHops("OpenAI", hops, 12)
	snapHops := sm.Get("OpenAI")
	if snapHops.Hops != 12 || len(snapHops.HopsList) != 1 {
		t.Fatalf("expected 12 hops, got %d", snapHops.Hops)
	}

	// Next HTTP probe without hops should preserve previous hops
	sm.Update("OpenAI", &ProbeSnapshot{Target: tgt, TCP: 60 * time.Millisecond})
	snapPreserved := sm.Get("OpenAI")
	if snapPreserved.Hops != 12 || len(snapPreserved.HopsList) != 1 {
		t.Fatalf("expected preserved 12 hops, got %d", snapPreserved.Hops)
	}
}
