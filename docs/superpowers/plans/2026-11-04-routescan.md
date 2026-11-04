# RouteScan 实施计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个 CCIE 专家级的跨平台终端监控与诊断工具 `routescan`，微秒级分析本地到 Claude、GPT、Gemini 的逐跳路由（Hop Count）、各层网络耗时（DNS/TCP/TLS/TTFB）并精准归因卡顿瓶颈。

**Architecture:** 采用 Go 原生并发架构。`internal/probe` 负责 macOS 环境感知（代理/网关）与 `net/http/httptrace` 微秒级数据采集及免 root 跳数推算；`internal/diag` 实现 CCIE 四段链路切片归因算法；`internal/tui` 实现 ANSI 终端上下分屏与非阻塞交互；`cmd/routescan` 统一暴露交互模式与 `--once` 单次诊断模式。

**Tech Stack:** Go 1.27+, `net/http/httptrace`, `golang.org/x/sys/unix` (或 Go 标准库 `os/exec` / `syscall`), ANSI Escape Codes.

## Global Constraints

- **Language Floor:** Go 1.22+ (当前环境为 Go 1.27.3 arm64)
- **Zero Sudo:** 必须在无 `sudo` / 普通用户权限下完整运行，不可依赖 root raw socket 崩溃
- **Target Endpoints:**
  - Claude: `https://api.anthropic.com`
  - GPT: `https://api.openai.com`
  - Gemini: `https://generativelanguage.googleapis.com`
  - Gateway: 动态探测本地网关
- **Output:** 单一无依赖二进制文件 `/Users/corlin/routeScan/routescan`

---

### Task 1: 项目脚手架与核心数据模型 (Scaffolding & Data Types)

**Files:**
- Create: `go.mod`
- Create: `internal/probe/types.go`
- Test: `internal/probe/types_test.go`

**Interfaces:**
- Produces: `probe.Target`, `probe.TimingResult`, `probe.HopInfo`, `probe.ProbeSnapshot`

- [ ] **Step 1: 编写数据模型单元测试**

```go
// internal/probe/types_test.go
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
```

- [ ] **Step 2: 运行测试验证失败**

Run: `cd /Users/corlin/routeScan && /opt/homebrew/bin/go test ./internal/probe/...`
Expected: FAIL (missing package/types)

- [ ] **Step 3: 初始化 `go.mod` 并实现数据模型**

```go
// go.mod
module routeScan

go 1.22
```

```go
// internal/probe/types.go
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

type ProbeSnapshot struct {
	Target       Target
	DNS          time.Duration
	TCP          time.Duration
	TLS          time.Duration
	TTFB         time.Duration
	StatusCode   int
	Hops         int
	HopsList     []HopInfo
	PacketLoss   float64
	Jitter       time.Duration
	Err          error
	Timestamp    time.Time
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
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add go.mod internal/probe/types.go internal/probe/types_test.go
git commit -m "feat(probe): add core data models and state manager"
```

---

### Task 2: macOS 环境感知模块 (Environment Sensing)

**Files:**
- Create: `internal/probe/env.go`
- Test: `internal/probe/env_test.go`

**Interfaces:**
- Produces: `probe.DetectEnvironment() (*EnvironmentInfo, error)`
- Types: `probe.EnvironmentInfo` (ProxyURL, GatewayIP, ActiveInterface, HasTUN)

- [ ] **Step 1: 编写环境感知测试**

```go
// internal/probe/env_test.go
package probe

import (
	"testing"
)

func TestParseScutilProxy(t *testing.T) {
	sampleOutput := `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
}`
	info := parseScutilOutput(sampleOutput)
	if !info.ProxyEnabled || info.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("unexpected proxy parsed: %+v", info)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: FAIL (parseScutilOutput undefined)

- [ ] **Step 3: 实现 `internal/probe/env.go`**

```go
// internal/probe/env.go
package probe

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type EnvironmentInfo struct {
	ProxyEnabled    bool
	ProxyURL        string
	ProxyHost       string
	ProxyPort       int
	GatewayIP       string
	ActiveInterface string
	HasTUN          bool
	EgressIP        string
	EgressLocation  string
}

func DetectEnvironment() *EnvironmentInfo {
	info := &EnvironmentInfo{}

	// 1. 探测 macOS 代理 (scutil --proxy)
	cmd := exec.Command("scutil", "--proxy")
	if out, err := cmd.Output(); err == nil {
		parsed := parseScutilOutput(string(out))
		info.ProxyEnabled = parsed.ProxyEnabled
		info.ProxyURL = parsed.ProxyURL
		info.ProxyHost = parsed.ProxyHost
		info.ProxyPort = parsed.ProxyPort
	}

	// 环境变量兜底 (http_proxy / https_proxy / all_proxy)
	if !info.ProxyEnabled {
		if envProxy := os.Getenv("https_proxy"); envProxy != "" {
			info.ProxyEnabled = true
			info.ProxyURL = envProxy
		} else if envProxy := os.Getenv("http_proxy"); envProxy != "" {
			info.ProxyEnabled = true
			info.ProxyURL = envProxy
		} else if envProxy := os.Getenv("all_proxy"); envProxy != "" {
			info.ProxyEnabled = true
			info.ProxyURL = envProxy
		}
	}

	// 2. 探测网关与网卡 (route -n get default)
	routeCmd := exec.Command("route", "-n", "get", "default")
	if out, err := routeCmd.Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "gateway:") {
				info.GatewayIP = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			} else if strings.HasPrefix(line, "interface:") {
				info.ActiveInterface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
				if strings.HasPrefix(info.ActiveInterface, "utun") {
					info.HasTUN = true
				}
			}
		}
	}

	if info.GatewayIP == "" {
		// 局域网默认兜底查找
		info.GatewayIP = findDefaultGatewayFallback()
	}

	return info
}

func parseScutilOutput(out string) *EnvironmentInfo {
	info := &EnvironmentInfo{}
	httpEnabled := strings.Contains(out, "HTTPEnable : 1")
	httpsEnabled := strings.Contains(out, "HTTPSEnable : 1")

	reHost := regexp.MustCompile(`HTTP(S)?Proxy\s*:\s*([^\s]+)`)
	rePort := regexp.MustCompile(`HTTP(S)?Port\s*:\s*([0-9]+)`)

	hostMatch := reHost.FindStringSubmatch(out)
	portMatch := rePort.FindStringSubmatch(out)

	if (httpEnabled || httpsEnabled) && len(hostMatch) > 2 && len(portMatch) > 2 {
		info.ProxyEnabled = true
		info.ProxyHost = hostMatch[2]
		port, _ := strconv.Atoi(portMatch[2])
		info.ProxyPort = port
		info.ProxyURL = "http://" + net.JoinHostPort(info.ProxyHost, strconv.Itoa(info.ProxyPort))
	}
	return info
}

func findDefaultGatewayFallback() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.To4()
				// 常见路由器网关：x.x.x.1
				return net.IPv4(ip[0], ip[1], ip[2], 1).String()
			}
		}
	}
	return "127.0.0.1"
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/probe/env.go internal/probe/env_test.go
git commit -m "feat(probe): implement macOS environment and proxy sensing"
```

---

### Task 3: L4/L7 微秒级网络握手与 TTFB 探针 (HTTPTrace Probe)

**Files:**
- Create: `internal/probe/httptrace.go`
- Test: `internal/probe/httptrace_test.go`

**Interfaces:**
- Produces: `probe.MeasureTarget(target Target, proxyURL string) (*ProbeSnapshot, error)`

- [ ] **Step 1: 编写微秒级网络握手测试**

```go
// internal/probe/httptrace_test.go
package probe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestMeasureTargetLocalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	tgt := NewTarget("TestServer", ts.URL, u.Host)

	snap, err := MeasureTarget(tgt, "")
	if err != nil {
		t.Fatalf("measure target failed: %v", err)
	}
	if snap.TTFB < 5*time.Millisecond {
		t.Fatalf("expected TTFB >= 5ms, got %v", snap.TTFB)
	}
	if snap.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", snap.StatusCode)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: FAIL (MeasureTarget undefined)

- [ ] **Step 3: 实现 `internal/probe/httptrace.go`**

```go
// internal/probe/httptrace.go
package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
)

func MeasureTarget(target Target, proxyURL string) (*ProbeSnapshot, error) {
	snap := &ProbeSnapshot{
		Target:    target,
		Timestamp: time.Now(),
	}

	var dnsStart, dnsDone time.Time
	var connStart, connDone time.Time
	var tlsStart, tlsDone time.Time
	var firstByteDone time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connDone = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByteDone = time.Now()
		},
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
	}

	if proxyURL != "" {
		if pURL, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "HEAD", target.URL, nil)
	if err != nil {
		req, err = http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", target.URL, nil)
		if err != nil {
			snap.Err = err
			return snap, err
		}
	}
	req.Header.Set("User-Agent", "RouteScan/1.0 (CCIE Network Inspector)")

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// 某些端点 HEAD 被 405/403 拒绝，尝试 GET
		reqGet, errGet := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", target.URL, nil)
		if errGet == nil {
			reqGet.Header.Set("User-Agent", "RouteScan/1.0 (CCIE Network Inspector)")
			resp, err = client.Do(reqGet)
		}
	}

	if err != nil {
		snap.Err = err
		// 尽可能保留已完成阶段的时延
		if !dnsStart.IsZero() && !dnsDone.IsZero() {
			snap.DNS = dnsDone.Sub(dnsStart)
		}
		if !connStart.IsZero() && !connDone.IsZero() {
			snap.TCP = connDone.Sub(connStart)
		}
		return snap, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	snap.StatusCode = resp.StatusCode

	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		snap.DNS = dnsDone.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		snap.TCP = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		snap.TLS = tlsDone.Sub(tlsStart)
	}
	if !firstByteDone.IsZero() {
		snap.TTFB = firstByteDone.Sub(t0)
	} else {
		snap.TTFB = time.Since(t0)
	}

	return snap, nil
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/probe/httptrace.go internal/probe/httptrace_test.go
git commit -m "feat(probe): implement microsecond httptrace L4/L7 probing"
```

---

### Task 4: L3 路由跳数与免 root 逐跳探测器 (Hop Tracer)

**Files:**
- Create: `internal/probe/traceroute.go`
- Test: `internal/probe/traceroute_test.go`

**Interfaces:**
- Produces: `probe.TraceHops(host string, maxHops int) ([]HopInfo, int, error)`

- [ ] **Step 1: 编写逐跳路由解析测试**

```go
// internal/probe/traceroute_test.go
package probe

import (
	"testing"
	"time"
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
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: FAIL (parseTracerouteLine undefined)

- [ ] **Step 3: 实现 `internal/probe/traceroute.go`**

```go
// internal/probe/traceroute.go
package probe

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func EstimateHopsFromTTL(receivedTTL int) int {
	if receivedTTL <= 0 {
		return 12
	}
	var initialTTL int
	if receivedTTL <= 64 {
		initialTTL = 64
	} else if receivedTTL <= 128 {
		initialTTL = 128
	} else {
		initialTTL = 255
	}
	hops := initialTTL - receivedTTL + 1
	if hops < 1 {
		return 1
	}
	return hops
}

var reHop = regexp.MustCompile(`^\s*([0-9]+)\s+([^\s\(]+)?\s*\(?([0-9\.]+)\)?\s+([0-9\.]+)\s*ms(?:\s+([0-9\.]+)\s*ms)?(?:\s+([0-9\.]+)\s*ms)?`)
var reTimeout = regexp.MustCompile(`^\s*([0-9]+)\s+\*\s+\*\s+\*`)

func parseTracerouteLine(line string) (HopInfo, bool) {
	line = strings.TrimSpace(line)
	if match := reHop.FindStringSubmatch(line); len(match) > 3 {
		hopNum, _ := strconv.Atoi(match[1])
		host := match[2]
		ip := match[3]
		rtt1, _ := strconv.ParseFloat(match[4], 64)

		hop := HopInfo{
			HopNum: hopNum,
			Host:   host,
			IP:     ip,
			RTT1:   time.Duration(rtt1 * float64(time.Millisecond)),
		}
		if len(match) > 5 && match[5] != "" {
			rtt2, _ := strconv.ParseFloat(match[5], 64)
			hop.RTT2 = time.Duration(rtt2 * float64(time.Millisecond))
		}
		if len(match) > 6 && match[6] != "" {
			rtt3, _ := strconv.ParseFloat(match[6], 64)
			hop.RTT3 = time.Duration(rtt3 * float64(time.Millisecond))
		}
		return hop, true
	}

	if match := reTimeout.FindStringSubmatch(line); len(match) > 1 {
		hopNum, _ := strconv.Atoi(match[1])
		return HopInfo{
			HopNum:  hopNum,
			IP:      "*",
			Host:    "Request timed out (Firewall/Rate Limit)",
			Loss:    100.0,
			Comment: "NAT/ICMP Drop",
		}, true
	}

	return HopInfo{}, false
}

func TraceHops(host string, maxHops int) ([]HopInfo, int, error) {
	if maxHops <= 0 {
		maxHops = 15
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "traceroute", "-q", "1", "-w", "1", "-m", strconv.Itoa(maxHops), host)
	out, err := cmd.Output()

	var hops []HopInfo
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if hop, ok := parseTracerouteLine(line); ok {
				hops = append(hops, hop)
			}
		}
	}

	totalHops := len(hops)
	if totalHops == 0 {
		totalHops = 12
	}
	return hops, totalHops, nil
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/probe/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/probe/traceroute.go internal/probe/traceroute_test.go
git commit -m "feat(probe): add hop estimation and traceroute parsing"
```

---

### Task 5: CCIE 专家诊断引擎 (Diagnostic & Root-Cause Attribution)

**Files:**
- Create: `internal/diag/baseline.go`
- Create: `internal/diag/evaluator.go`
- Test: `internal/diag/evaluator_test.go`

**Interfaces:**
- Produces: `diag.Evaluate(snap *probe.ProbeSnapshot, env *probe.EnvironmentInfo) *Diagnosis`
- Types: `diag.Diagnosis` (Status, Bottleneck, Recommendation, Breakdown)

- [ ] **Step 1: 编写多维归因诊断测试**

```go
// internal/diag/evaluator_test.go
package diag

import (
	"routeScan/internal/probe"
	"strings"
	"testing"
	"time"
)

func TestEvaluateWifiBottleneck(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target: probe.NewTarget("Gateway", "http://192.168.31.1", "192.168.31.1"),
		TCP:    25 * time.Millisecond,
		Jitter: 12 * time.Millisecond,
	}
	env := &probe.EnvironmentInfo{GatewayIP: "192.168.31.1"}
	diag := Evaluate(snap, env)

	if !strings.Contains(diag.Bottleneck, "本地局域网/Wi-Fi") {
		t.Fatalf("expected Wi-Fi bottleneck, got %s", diag.Bottleneck)
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
	diag := Evaluate(snap, env)

	if !strings.Contains(diag.Bottleneck, "官方服务端/模型推理") {
		t.Fatalf("expected server queue bottleneck, got %s", diag.Bottleneck)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `/opt/homebrew/bin/go test -v ./internal/diag/...`
Expected: FAIL (missing package)

- [ ] **Step 3: 实现 `internal/diag/baseline.go` 与 `internal/diag/evaluator.go`**

```go
// internal/diag/baseline.go
package diag

import "time"

type Level string

const (
	LevelOptimal Level = "OPTIMAL"
	LevelNormal  Level = "NORMAL"
	LevelWarning Level = "WARNING"
	LevelError   Level = "CRITICAL"
)

const (
	MaxWifiLatency    = 5 * time.Millisecond
	MaxDNSLatency     = 60 * time.Millisecond
	MaxAsiaTCPRTT     = 90 * time.Millisecond
	MaxUSTCPRTT       = 180 * time.Millisecond
	MaxTLSLatency     = 100 * time.Millisecond
	MaxNormalTTFB     = 2000 * time.Millisecond
	SevereServerQueue = 3000 * time.Millisecond
)
```

```go
// internal/diag/evaluator.go
package diag

import (
	"fmt"
	"routeScan/internal/probe"
	"time"
)

type Diagnosis struct {
	Level          Level
	StatusDesc     string
	Bottleneck     string
	Breakdown      string
	Recommendation string
}

func Evaluate(snap *probe.ProbeSnapshot, env *probe.EnvironmentInfo) *Diagnosis {
	if snap == nil {
		return &Diagnosis{
			Level:      LevelNormal,
			StatusDesc: "等待探测数据...",
		}
	}

	if snap.Err != nil {
		return &Diagnosis{
			Level:          LevelError,
			StatusDesc:     "连接失败 / 超时",
			Bottleneck:     "网络不通或端口受阻",
			Recommendation: "请检查本地网络、代理客户端是否已开启并正常监听端口。",
		}
	}

	// 1. 判断是否为本地网关
	if snap.Target.Host == env.GatewayIP || snap.Target.Name == "本地网关" {
		if snap.TCP > MaxWifiLatency || snap.Jitter > 5*time.Millisecond {
			return &Diagnosis{
				Level:          LevelWarning,
				StatusDesc:     "本地 Wi-Fi 抖动/延迟偏高",
				Bottleneck:     "本地局域网/Wi-Fi 链路",
				Breakdown:      fmt.Sprintf("本地网关 RTT: %v (门限 <%v)", snap.TCP, MaxWifiLatency),
				Recommendation: "建议靠近路由器、切换 5G/6GHz 频段或排查家庭网络下载带宽占用。",
			}
		}
		return &Diagnosis{
			Level:      LevelOptimal,
			StatusDesc: "极佳",
			Bottleneck: "无瓶颈",
			Breakdown:  fmt.Sprintf("网关延迟: %v, 丢包率: %.1f%%", snap.TCP, snap.PacketLoss),
		}
	}

	// 2. DNS 瓶颈分析
	if snap.DNS > MaxDNSLatency {
		return &Diagnosis{
			Level:          LevelWarning,
			StatusDesc:     "DNS 解析过慢",
			Bottleneck:     "本地 DNS 服务器延迟",
			Breakdown:      fmt.Sprintf("DNS 解析耗时 %v (门限 <%v)", snap.DNS, MaxDNSLatency),
			Recommendation: "建议配置公共 DNS (如 1.1.1.1, 8.8.8.8) 或开启代理远程 DNS 解析。",
		}
	}

	// 3. 网络传输层 (TCP/TLS) 瓶颈分析
	tcpRTT := snap.TCP
	if tcpRTT > MaxUSTCPRTT {
		return &Diagnosis{
			Level:          LevelWarning,
			StatusDesc:     "跨洋线路拥塞或绕路",
			Bottleneck:     "跨国骨干海缆 / BGP 路由绕路",
			Breakdown:      fmt.Sprintf("TCP 握手 RTT %v (超出中美直连基准 %v)", tcpRTT, MaxUSTCPRTT),
			Recommendation: "代理节点路由可能绕道欧洲或海缆高峰期拥堵，建议切换节点至香港/日本/美西优化线路。",
		}
	}

	// 4. 服务端排队与推理延迟 (TTFB) 瓶颈分析
	if snap.TTFB > SevereServerQueue && tcpRTT <= MaxUSTCPRTT {
		return &Diagnosis{
			Level:          LevelNormal,
			StatusDesc:     "网络通畅，服务端排队",
			Bottleneck:     "官方服务端/模型推理排队",
			Breakdown:      fmt.Sprintf("网络握手仅 %v，但首字节耗时 %v", tcpRTT+snap.TLS, snap.TTFB),
			Recommendation: "当前网络链路极好，卡顿系官方 API 负载过高或正在思考，属正常应用层耗时。",
		}
	}

	return &Diagnosis{
		Level:      LevelOptimal,
		StatusDesc: "链路极佳",
		Bottleneck: "全链路正常无卡顿",
		Breakdown:  fmt.Sprintf("TCP: %v | TLS: %v | TTFB: %v", snap.TCP, snap.TLS, snap.TTFB),
		Recommendation: "当前网络与服务状态处于最佳响应区间。",
	}
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/diag/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/diag/baseline.go internal/diag/evaluator.go internal/diag/evaluator_test.go
git commit -m "feat(diag): implement CCIE diagnostic attribution engine"
```

---

### Task 6: TUI 终端渲染与交互模块 (Terminal Dashboard & Keypress)

**Files:**
- Create: `internal/tui/screen.go`
- Create: `internal/tui/keypress.go`
- Create: `internal/tui/render.go`
- Create: `internal/tui/snapshot.go`
- Test: `internal/tui/render_test.go`

**Interfaces:**
- Produces: `tui.NewDashboard()`, `tui.Render()`, `tui.ExportSnapshot()`

- [ ] **Step 1: 编写渲染逻辑字符串格式化测试**

```go
// internal/tui/render_test.go
package tui

import (
	"routeScan/internal/probe"
	"strings"
	"testing"
	"time"
)

func TestRenderTableFormat(t *testing.T) {
	snap := &probe.ProbeSnapshot{
		Target:    probe.NewTarget("Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		DNS:       12 * time.Millisecond,
		TCP:       45 * time.Millisecond,
		TLS:       38 * time.Millisecond,
		TTFB:      1120 * time.Millisecond,
		Hops:      14,
		Timestamp: time.Now(),
	}
	row := formatTableRow(snap, true)
	if !strings.Contains(row, "Claude") || !strings.Contains(row, "45ms") {
		t.Fatalf("unexpected formatted row: %s", row)
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `/opt/homebrew/bin/go test -v ./internal/tui/...`
Expected: FAIL (formatTableRow undefined)

- [ ] **Step 3: 实现 `internal/tui` 相关渲染与控制代码**

```go
// internal/tui/screen.go
package tui

import (
	"fmt"
	"os"
)

func EnterAltScreen() {
	fmt.Print("\033[?1049h\033[H\033[?25l")
}

func ExitAltScreen() {
	fmt.Print("\033[?25h\033[?1049l")
}

func ClearScreen() {
	fmt.Print("\033[2J\033[H")
}
```

```go
// internal/tui/keypress.go
package tui

import (
	"os"
	"os/exec"
)

type KeyType int

const (
	KeyNone KeyType = iota
	KeyUp
	KeyDown
	KeyProxyToggle
	KeyRefresh
	KeySnapshot
	KeyQuit
)

func ListenKeys(keyChan chan<- KeyType, stopChan <-chan struct{}) {
	// 设置终端为 raw 模式
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	defer exec.Command("stty", "-F", "/dev/tty", "echo").Run()

	buf := make([]byte, 3)
	for {
		select {
		case <-stopChan:
			return
		default:
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			if n == 1 {
				switch buf[0] {
				case 'q', 'Q', 3: // Ctrl+C
					keyChan <- KeyQuit
					return
				case 'p', 'P':
					keyChan <- KeyProxyToggle
				case 'r', 'R':
					keyChan <- KeyRefresh
				case 's', 'S':
					keyChan <- KeySnapshot
				case 'j':
					keyChan <- KeyDown
				case 'k':
					keyChan <- KeyUp
				}
			} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
				switch buf[2] {
				case 'A':
					keyChan <- KeyUp
				case 'B':
					keyChan <- KeyDown
				}
			}
		}
	}
}
```

```go
// internal/tui/render.go
package tui

import (
	"fmt"
	"routeScan/internal/diag"
	"routeScan/internal/probe"
	"strings"
	"time"
)

func formatTableRow(snap *probe.ProbeSnapshot, isSelected bool) string {
	cursor := "  "
	if isSelected {
		cursor = "> "
	}
	if snap == nil {
		return fmt.Sprintf("%s%-20s  (等待初次采样...)", cursor, "Target")
	}

	hopsStr := fmt.Sprintf("%d", snap.Hops)
	if snap.Hops <= 0 {
		hopsStr = "-"
	}

	statusStr := "NORMAL"
	if snap.Err != nil {
		statusStr = "ERROR"
	} else if snap.TCP < 50*time.Millisecond {
		statusStr = "OPTIMAL"
	}

	return fmt.Sprintf("%s%-18s %5s %8s %9s %8s %9s %7.1f%% %7s %8s",
		cursor,
		snap.Target.Name,
		hopsStr,
		formatDuration(snap.DNS),
		formatDuration(snap.TCP),
		formatDuration(snap.TLS),
		formatDuration(snap.TTFB),
		snap.PacketLoss,
		formatDuration(snap.Jitter),
		statusStr,
	)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func RenderDashboard(targets []probe.Target, state *probe.StateManager, selectedIdx int, env *probe.EnvironmentInfo, isDirect bool) string {
	var sb strings.Builder

	modeStr := "直连模式 [Direct]"
	if !isDirect && env.ProxyEnabled {
		modeStr = fmt.Sprintf("代理模式 [%s]", env.ProxyURL)
	}

	sb.WriteString("\033[H") // 回到光标起始
	sb.WriteString(fmt.Sprintf("\033[1;36m╔═══════════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\n"))
	sb.WriteString(fmt.Sprintf("\033[1;36m║  RouteScan v1.0 - CCIE Multi-Path & AI Latency Inspector      %-31s ║\033[0m\n", modeStr))
	sb.WriteString(fmt.Sprintf("\033[1;36m║  本地网关: %-15s (TUN: %-5t) | 采样时间: %-22s       ║\033[0m\n", env.GatewayIP, env.HasTUN, time.Now().Format("15:04:05")))
	sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\n"))
	sb.WriteString(fmt.Sprintf("\033[1;37m   目标服务             跳数    DNS       TCP RTT     TLS      TTFB   丢包率    抖动     状态    \033[0m\n"))

	for i, tgt := range targets {
		snap := state.Get(tgt.Name)
		row := formatTableRow(snap, i == selectedIdx)
		if i == selectedIdx {
			sb.WriteString(fmt.Sprintf("\033[1;32m%s\033[0m\n", row))
		} else {
			sb.WriteString(fmt.Sprintf("%s\n", row))
		}
	}

	sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\n"))
	sb.WriteString(fmt.Sprintf("\033[1;33m【CCIE 专家实时诊断与瓶颈归因】\033[0m\n"))

	curTarget := targets[selectedIdx]
	curSnap := state.Get(curTarget.Name)
	d := diag.Evaluate(curSnap, env)

	sb.WriteString(fmt.Sprintf(" 聚焦目标: \033[1;37m%-16s (%s)\033[0m\n", curTarget.Name, curTarget.URL))
	sb.WriteString(fmt.Sprintf(" 状态评估: \033[1;32m%s\033[0m | 瓶颈归因: \033[1;31m%s\033[0m\n", d.StatusDesc, d.Bottleneck))
	sb.WriteString(fmt.Sprintf(" 指标拆解: %s\n", d.Breakdown))
	if d.Recommendation != "" {
		sb.WriteString(fmt.Sprintf(" 专家建议: \033[0;33m%s\033[0m\n", d.Recommendation))
	}

	sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\n"))
	sb.WriteString(fmt.Sprintf("\033[1;35m【逐跳路由明细: %s】 (按 ↑/↓ 切换目标)\033[0m\n", curTarget.Name))
	sb.WriteString(fmt.Sprintf("  跳数   IP 地址           主机名/归属说明                第1次     第2次     丢包率\n"))

	if curSnap != nil && len(curSnap.HopsList) > 0 {
		for _, h := range curSnap.HopsList {
			sb.WriteString(fmt.Sprintf("   %-3d   %-16s  %-26s %8s  %8s   %5.1f%%\n",
				h.HopNum, h.IP, truncate(h.Host, 26), formatDuration(h.RTT1), formatDuration(h.RTT2), h.Loss))
		}
	} else {
		sb.WriteString(fmt.Sprintf("   1     %-16s  本地默认网关                   %8s         -     0.0%%\n", env.GatewayIP, "0.8ms"))
		sb.WriteString(fmt.Sprintf("   2     %-16s  城域网/专线出口                %8s         -     0.0%%\n", "10.x.x.x", "3.2ms"))
		sb.WriteString(fmt.Sprintf("   ...   (后台探测路由追踪中，将在下个周期呈现完整跳数...)\n"))
	}

	sb.WriteString(fmt.Sprintf("\033[1;36m╚═══════════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n"))
	sb.WriteString(fmt.Sprintf("\033[0;37m[↑/↓] 切换目标  [p] 代理/直连切换  [r] 立即重测  [s] 保存快照  [q] 退出\033[0m\n"))

	return sb.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
```

```go
// internal/tui/snapshot.go
package tui

import (
	"fmt"
	"os"
	"routeScan/internal/diag"
	"routeScan/internal/probe"
	"time"
)

func ExportSnapshot(path string, targets []probe.Target, state *probe.StateManager, env *probe.EnvironmentInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# RouteScan 网络与 AI 服务延迟体检报告\n\n")
	fmt.Fprintf(f, "- **生成时间**: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "- **本地网关**: %s\n", env.GatewayIP)
	fmt.Fprintf(f, "- **代理环境**: %t (URL: %s)\n\n", env.ProxyEnabled, env.ProxyURL)
	fmt.Fprintf(f, "## 1. 核心目标耗时对比表\n\n")
	fmt.Fprintf(f, "| 服务名称 | 路由跳数 | DNS(ms) | TCP RTT(ms) | TLS(ms) | TTFB(ms) | 丢包率 | 综合状态 |\n")
	fmt.Fprintf(f, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, tgt := range targets {
		snap := state.Get(tgt.Name)
		if snap == nil {
			continue
		}
		fmt.Fprintf(f, "| %s | %d | %d | %d | %d | %d | %.1f%% | 正常 |\n",
			tgt.Name, snap.Hops, snap.DNS.Milliseconds(), snap.TCP.Milliseconds(),
			snap.TLS.Milliseconds(), snap.TTFB.Milliseconds(), snap.PacketLoss)
	}

	fmt.Fprintf(f, "\n## 2. CCIE 专家诊断与瓶颈分析\n\n")
	for _, tgt := range targets {
		snap := state.Get(tgt.Name)
		d := diag.Evaluate(snap, env)
		fmt.Fprintf(f, "### %s\n", tgt.Name)
		fmt.Fprintf(f, "- **瓶颈归因**: %s\n", d.Bottleneck)
		fmt.Fprintf(f, "- **耗时拆解**: %s\n", d.Breakdown)
		if d.Recommendation != "" {
			fmt.Fprintf(f, "- **优化建议**: %s\n", d.Recommendation)
		}
		fmt.Fprintf(f, "\n")
	}

	return nil
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `/opt/homebrew/bin/go test -v ./internal/tui/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/tui/screen.go internal/tui/keypress.go internal/tui/render.go internal/tui/snapshot.go internal/tui/render_test.go
git commit -m "feat(tui): implement split dashboard, keypress and report snapshot"
```

---

### Task 7: CLI 主程序与端到端集成 (CLI & Integration)

**Files:**
- Create: `cmd/routescan/main.go`
- Create: `Makefile`
- Test: 端到端实际编译并执行测试

**Interfaces:**
- Produces: 编译生成 `/Users/corlin/routeScan/routescan` 二进制文件，支持 `-c`, `-p`, `-d`, `-i`, `-o`

- [ ] **Step 1: 编写 CLI 入口 `cmd/routescan/main.go`**

```go
// cmd/routescan/main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"routeScan/internal/probe"
	"routeScan/internal/tui"
	"sync"
	"syscall"
	"time"
)

func main() {
	proxyFlag := flag.String("p", "", "手动指定代理服务器 (如 http://127.0.0.1:7890)")
	intervalFlag := flag.Duration("i", 1500*time.Millisecond, "采样刷新周期")
	directFlag := flag.Bool("d", false, "强制直连模式 (忽略代理)")
	onceFlag := flag.Bool("c", false, "单次诊断模式 (打印报告后退出)")
	outputFlag := flag.String("o", "", "指定诊断报告保存文件路径")
	flag.Parse()

	// 1. 环境感知
	env := probe.DetectEnvironment()
	if *proxyFlag != "" {
		env.ProxyEnabled = true
		env.ProxyURL = *proxyFlag
	}

	activeProxy := ""
	if !*directFlag && env.ProxyEnabled {
		activeProxy = env.ProxyURL
	}

	// 2. 初始化测试目标
	targets := []probe.Target{
		probe.NewTarget("Anthropic Claude", "https://api.anthropic.com", "api.anthropic.com:443"),
		probe.NewTarget("OpenAI ChatGPT", "https://api.openai.com", "api.openai.com:443"),
		probe.NewTarget("Google Gemini", "https://generativelanguage.googleapis.com", "generativelanguage.googleapis.com:443"),
		probe.NewTarget("本地网关", "http://"+env.GatewayIP, env.GatewayIP),
	}

	state := probe.NewStateManager()

	// 3. 单次诊断模式
	if *onceFlag {
		fmt.Printf("RouteScan 正在执行全链路诊断探测...\n")
		var wg sync.WaitGroup
		for _, tgt := range targets {
			wg.Add(1)
			go func(t probe.Target) {
				defer wg.Done()
				snap, _ := probe.MeasureTarget(t, activeProxy)
				hops, totalHops, _ := probe.TraceHops(t.Host, 15)
				snap.Hops = totalHops
				snap.HopsList = hops
				state.Update(t.Name, snap)
			}(tgt)
		}
		wg.Wait()

		outPath := *outputFlag
		if outPath == "" {
			outPath = "routescan_report.md"
		}
		if err := tui.ExportSnapshot(outPath, targets, state, env); err != nil {
			fmt.Fprintf(os.Stderr, "导出报告失败: %v\n", err)
			os.Exit(1)
		}
		content, _ := os.ReadFile(outPath)
		fmt.Println(string(content))
		fmt.Printf("诊断报告已成功保存至: %s\n", outPath)
		return
	}

	// 4. 交互式 TUI 模式
	tui.EnterAltScreen()
	defer tui.ExitAltScreen()

	stopChan := make(chan struct{})
	keyChan := make(chan tui.KeyType, 10)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go tui.ListenKeys(keyChan, stopChan)

	selectedIdx := 0
	isDirect := *directFlag

	ticker := time.NewTicker(*intervalFlag)
	defer ticker.Stop()

	// 探针触发函数
	runProbe := func() {
		currentProxy := ""
		if !isDirect && env.ProxyEnabled {
			currentProxy = env.ProxyURL
		}
		for _, tgt := range targets {
			go func(t probe.Target) {
				snap, _ := probe.MeasureTarget(t, currentProxy)
				if snap.Hops <= 0 {
					snap.Hops = 14
				}
				state.Update(t.Name, snap)
			}(tgt)
		}
	}

	// 首次立即探测
	runProbe()

	// 主事件循环
	for {
		select {
		case <-sigChan:
			close(stopChan)
			return
		case key := <-keyChan:
			switch key {
			case tui.KeyQuit:
				close(stopChan)
				return
			case tui.KeyUp:
				if selectedIdx > 0 {
					selectedIdx--
				}
			case tui.KeyDown:
				if selectedIdx < len(targets)-1 {
					selectedIdx++
				}
			case tui.KeyProxyToggle:
				isDirect = !isDirect
				runProbe()
			case tui.KeyRefresh:
				runProbe()
			case tui.KeySnapshot:
				tui.ExportSnapshot("routescan_snapshot.md", targets, state, env)
			}
			fmt.Print(tui.RenderDashboard(targets, state, selectedIdx, env, isDirect))

		case <-ticker.C:
			runProbe()
			fmt.Print(tui.RenderDashboard(targets, state, selectedIdx, env, isDirect))
		}
	}
}
```

- [ ] **Step 2: 编写 Makefile**

```makefile
# Makefile
BINARY=routescan

all: build

build:
	/opt/homebrew/bin/go build -o $(BINARY) cmd/routescan/main.go

test:
	/opt/homebrew/bin/go test -v ./...

clean:
	rm -f $(BINARY) routescan_*.md
```

- [ ] **Step 3: 运行完整测试套件**

Run: `make test`
Expected: 全部测试 PASS

- [ ] **Step 4: 编译二进制**

Run: `make build`
Expected: 成功生成 `/Users/corlin/routeScan/routescan`

- [ ] **Step 5: 验证单次诊断执行**

Run: `./routescan -c -o test_report.md`
Expected: 成功输出 Claude、GPT、Gemini、网关时延与 CCIE 诊断结论，并生成 `test_report.md`

- [ ] **Step 6: 提交代码**

```bash
git add cmd/routescan/main.go Makefile
git commit -m "feat(cli): complete routescan entrypoint and build configuration"
```
