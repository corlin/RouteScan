package probe

import (
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
