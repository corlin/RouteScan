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

	// 保持已探测到的逐跳路由信息，防止被常规 HTTP 探测的空跳数覆盖
	if prev, ok := s.Snapshots[name]; ok && prev != nil {
		if snap.Hops <= 0 && prev.Hops > 0 {
			snap.Hops = prev.Hops
		}
		if len(snap.HopsList) == 0 && len(prev.HopsList) > 0 {
			snap.HopsList = prev.HopsList
		}
	}

	hist := append(s.History[name], snap)
	if len(hist) > 30 {
		hist = hist[1:]
	}
	s.History[name] = hist

	// 结合滑动窗口历史记录（成功/失败）自动计算真实滑动丢包率
	lostCount := 0
	for _, item := range hist {
		if item != nil && item.Err != nil {
			lostCount++
		}
	}
	if len(hist) > 0 {
		snap.PacketLoss = (float64(lostCount) / float64(len(hist))) * 100.0
	}

	// 根据相邻两次有效 RTT 计算网络抖动 Jitter
	if len(hist) >= 2 && snap.Err == nil {
		prevSnap := hist[len(hist)-2]
		if prevSnap != nil && prevSnap.Err == nil {
			rttCur := snap.TCP
			if rttCur == 0 {
				rttCur = snap.TLS
			}
			rttPrev := prevSnap.TCP
			if rttPrev == 0 {
				rttPrev = prevSnap.TLS
			}
			if rttCur > 0 && rttPrev > 0 {
				diff := rttCur - rttPrev
				if diff < 0 {
					diff = -diff
				}
				snap.Jitter = diff
			}
		}
	}

	s.Snapshots[name] = snap
}

func (s *StateManager) UpdateHops(name string, hops []HopInfo, totalHops int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap, ok := s.Snapshots[name]; ok && snap != nil {
		snap.Hops = totalHops
		snap.HopsList = hops
	} else {
		s.Snapshots[name] = &ProbeSnapshot{
			Hops:     totalHops,
			HopsList: hops,
		}
	}
}

func (s *StateManager) Get(name string) *ProbeSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Snapshots[name]
}
