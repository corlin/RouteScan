package probe

import (
	"sync"
	"time"
)

type Target struct {
	Name    string
	URL     string
	Host    string
	IsProxy bool
}

func NewTarget(name, rawURL, host string) Target {
	return Target{
		Name: name,
		URL:  rawURL,
		Host: host,
	}
}

type HopInfo struct {
	HopNum  int
	IP      string
	Host    string
	RTT1    time.Duration
	RTT2    time.Duration
	RTT3    time.Duration
	Loss    float64
	Comment string
}

type TimingResult struct {
	DNS  time.Duration
	TCP  time.Duration
	TLS  time.Duration
	TTFB time.Duration
}

type ProbeSnapshot struct {
	Target     Target
	DNS        time.Duration
	TCP        time.Duration
	TLS        time.Duration
	TTFB       time.Duration
	StatusCode int
	Hops       int
	HopsList   []HopInfo
	PacketLoss float64
	Jitter     time.Duration
	Err        error
	Timestamp  time.Time
}

func (p *ProbeSnapshot) TotalHandshake() time.Duration {
	return p.TCP + p.TLS
}

type StateManager struct {
	mu        sync.RWMutex
	Snapshots map[string]*ProbeSnapshot
	History   map[string][]*ProbeSnapshot
}

func NewStateManager() *StateManager {
	return &StateManager{
		Snapshots: make(map[string]*ProbeSnapshot),
		History:   make(map[string][]*ProbeSnapshot),
	}
}

func (s *StateManager) Update(name string, snap *ProbeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Snapshots[name] = snap
	s.History[name] = append(s.History[name], snap)
	if len(s.History[name]) > 30 {
		s.History[name] = s.History[name][1:]
	}
}

func (s *StateManager) Get(name string) *ProbeSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Snapshots[name]
}
