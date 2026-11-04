# RouteScan 本地 GeoIP 与 ASN 路由分析实施计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 RouteScan 增加纯本地 GeoIP 与自治域 (ASN) 路由分析引擎，精确标注逐跳网络节点（Hop）的国家、省份、城市、运营商及 AS 组织，实现毫秒级本地分析与无缝自愈。

**Architecture:** 采用分层解析引擎 `internal/geoip`：L1 内存规则树秒级识别私有地址与骨干网，L2 通过 `maxminddb-golang` 二叉树检索本地 MMDB 数据库，L3 自动管理 `~/.routescan/geoip.mmdb` 的静默下载与热重载。在 `probe.TraceHops` 中完成逐跳注入，并在 `tui` 中渲染 NextTrace 风格紧凑展示。

**Tech Stack:** Go 1.22+, `github.com/oschwald/maxminddb-golang`, MMDB, ANSI Terminal.

---

### Task 1: 核心数据模型与静态规则引擎 (Types & Built-in Rules)

**Files:**
- Create: `internal/geoip/types.go`
- Create: `internal/geoip/rules.go`
- Test: `internal/geoip/rules_test.go`

**Interfaces:**
- Produces: `geoip.GeoLocation`, `geoip.MatchBuiltinRule(ip net.IP) (*GeoLocation, bool)`

- [ ] **Step 1: 编写规则匹配单元测试**

```go
// internal/geoip/rules_test.go
package geoip

import (
	"net"
	"testing"
)

func TestMatchBuiltinRule(t *testing.T) {
	tests := []struct {
		ip       string
		wantType string
	}{
		{"127.0.0.1", "回环地址"},
		{"192.168.1.1", "局域网"},
		{"10.0.0.1", "局域网"},
		{"100.64.0.1", "城域网"},
		{"172.20.1.1", "局域网"},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		loc, matched := MatchBuiltinRule(ip)
		if !matched {
			t.Fatalf("expected %s to match builtin rule", tt.ip)
		}
		if loc.City == "" && loc.Country == "" {
			t.Fatalf("expected location info for %s", tt.ip)
		}
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

Run: `go test ./internal/geoip/...`
Expected: FAIL (package/function not found)

- [ ] **Step 3: 实现 `types.go` 与 `rules.go`**

```go
// internal/geoip/types.go
package geoip

import "fmt"

type GeoLocation struct {
	Country string
	Region  string
	City    string
	ASN     string
	Org     string
}

func (g *GeoLocation) String() string {
	if g == nil {
		return "未知位置"
	}
	geo := ""
	if g.Country != "" {
		geo += g.Country
	}
	if g.Region != "" && g.Region != g.Country {
		if geo != "" {
			geo += " "
		}
		geo += g.Region
	}
	if g.City != "" && g.City != g.Region {
		if geo != "" {
			geo += " "
		}
		geo += g.City
	}
	asInfo := ""
	if g.ASN != "" || g.Org != "" {
		if g.ASN != "" && g.Org != "" {
			asInfo = fmt.Sprintf("(%s %s)", g.ASN, g.Org)
		} else if g.ASN != "" {
			asInfo = fmt.Sprintf("(%s)", g.ASN)
		} else {
			asInfo = fmt.Sprintf("(%s)", g.Org)
		}
	}
	if asInfo != "" {
		if geo != "" {
			return geo + " " + asInfo
		}
		return asInfo
	}
	if geo == "" {
		return "公网节点"
	}
	return geo
}
```

```go
// internal/geoip/rules.go
package geoip

import (
	"net"
)

var (
	cgnatNet = net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)}
)

func MatchBuiltinRule(ip net.IP) (*GeoLocation, bool) {
	if ip == nil {
		return nil, false
	}
	if ip.IsLoopback() {
		return &GeoLocation{
			Country: "[本机]",
			City:    "Loopback 本地回环",
		}, true
	}
	if ip.IsPrivate() {
		return &GeoLocation{
			Country: "[局域网]",
			City:    "本地局域网 / 家庭网关",
		}, true
	}
	if cgnatNet.Contains(ip) {
		return &GeoLocation{
			Country: "[局端]",
			City:    "运营商城域网汇聚网关 (CGNAT)",
			Org:     "Carrier Grade NAT",
		}, true
	}
	return nil, false
}
```

- [ ] **Step 4: 运行测试验证通过**

Run: `go test -v ./internal/geoip/...`
Expected: PASS

- [ ] **Step 5: 提交代码**

```bash
git add internal/geoip/types.go internal/geoip/rules.go internal/geoip/rules_test.go
git commit -m "feat(geoip): add core geoip data types and builtin network rules"
```

---

### Task 2: 本地 MMDB 数据库解析与 Lookup 管道 (MMDB Engine)

**Files:**
- Create: `internal/geoip/db.go`
- Test: `internal/geoip/db_test.go`
- Modify: `go.mod` (引入 `github.com/oschwald/maxminddb-golang`)

**Interfaces:**
- Produces: `geoip.NewManager(dbPath string) *Manager`, `manager.Lookup(ipStr string) *GeoLocation`

- [ ] **Step 1: 安装依赖并编写测试**

```bash
go get github.com/oschwald/maxminddb-golang
```

```go
// internal/geoip/db_test.go
package geoip

import (
	"testing"
)

func TestLookupBuiltinFallback(t *testing.T) {
	mgr := NewManager("") // 无 mmdb 路径
	loc := mgr.Lookup("192.168.1.1")
	if loc == nil || loc.Country != "[局域网]" {
		t.Fatalf("expected builtin match, got %+v", loc)
	}

	locPublic := mgr.Lookup("1.1.1.1")
	if locPublic == nil {
		t.Fatalf("expected fallback location, got nil")
	}
}
```

- [ ] **Step 2: 实现 `internal/geoip/db.go`**

```go
// internal/geoip/db.go
package geoip

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type Manager struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	dbPath string
}

func NewManager(dbPath string) *Manager {
	mgr := &Manager{dbPath: dbPath}
	if dbPath != "" {
		mgr.LoadDB(dbPath)
	}
	return mgr
}

func (m *Manager) LoadDB(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		return err
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	if m.reader != nil {
		m.reader.Close()
	}
	m.reader = r
	m.dbPath = path
	return nil
}

type mmdbRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		IsoCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

func (m *Manager) Lookup(ipStr string) *GeoLocation {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// 1. 优先内置特征匹配 (RFC 1918 / CGNAT / Loopback)
	if loc, matched := MatchBuiltinRule(ip); matched {
		return loc
	}

	// 2. 本地 MMDB 检索
	m.mu.RLock()
	reader := m.reader
	m.mu.RUnlock()

	if reader != nil {
		var record mmdbRecord
		if err := reader.Lookup(ip, &record); err == nil {
			loc := &GeoLocation{}
			if name, ok := record.Country.Names["zh-CN"]; ok {
				loc.Country = name
			} else if name, ok := record.Country.Names["en"]; ok {
				loc.Country = name
			} else if record.Country.IsoCode != "" {
				loc.Country = record.Country.IsoCode
			}

			if len(record.Subdivisions) > 0 {
				if name, ok := record.Subdivisions[0].Names["zh-CN"]; ok {
					loc.Region = name
				} else if name, ok := record.Subdivisions[0].Names["en"]; ok {
					loc.Region = name
				}
			}

			if name, ok := record.City.Names["zh-CN"]; ok {
				loc.City = name
			} else if name, ok := record.City.Names["en"]; ok {
				loc.City = name
			}

			if record.AutonomousSystemNumber > 0 {
				loc.ASN = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			}
			if record.AutonomousSystemOrganization != "" {
				loc.Org = record.AutonomousSystemOrganization
			}

			if loc.Country != "" || loc.City != "" || loc.ASN != "" {
				return loc
			}
		}
	}

	// 3. 兜底未匹配
	return &GeoLocation{
		Country: "公网节点",
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader != nil {
		m.reader.Close()
		m.reader = nil
	}
}
```

- [ ] **Step 3: 运行测试验证通过**

Run: `go test -v ./internal/geoip/...`
Expected: PASS

- [ ] **Step 4: 提交代码**

```bash
git add go.mod go.sum internal/geoip/db.go internal/geoip/db_test.go
git commit -m "feat(geoip): implement local mmdb reader and lookup pipeline"
```

---

### Task 3: 数据库自动下载与热重载 (Downloader & Hot Reload)

**Files:**
- Create: `internal/geoip/downloader.go`
- Test: `internal/geoip/downloader_test.go`

**Interfaces:**
- Produces: `geoip.DefaultDBPath() string`, `geoip.EnsureDatabase(mgr *Manager, autoDownload bool) error`

- [ ] **Step 1: 编写测试**

```go
// internal/geoip/downloader_test.go
package geoip

import (
	"strings"
	"testing"
)

func TestDefaultDBPath(t *testing.T) {
	path := DefaultDBPath()
	if !strings.Contains(path, ".routescan") || !strings.HasSuffix(path, "geoip.mmdb") {
		t.Fatalf("unexpected default path: %s", path)
	}
}
```

- [ ] **Step 2: 实现 `internal/geoip/downloader.go`**

```go
// internal/geoip/downloader.go
package geoip

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// 开源精简版全球 IP/ASN mmdb 镜像源
	OpenMMDBURL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"
)

func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".routescan", "geoip.mmdb")
}

func DownloadDatabase(destPath string) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile := destPath + ".tmp"
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Get(OpenMMDBURL)
	if err != nil {
		return fmt.Errorf("下载 MMDB 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 MMDB 失败，HTTP 状态码: %d", resp.StatusCode)
	}

	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	out.Close()
	return os.Rename(tmpFile, destPath)
}

func EnsureDatabase(mgr *Manager, autoDownload bool) {
	targetPath := mgr.dbPath
	if targetPath == "" {
		targetPath = DefaultDBPath()
	}

	if _, err := os.Stat(targetPath); err == nil {
		mgr.LoadDB(targetPath)
		return
	}

	if autoDownload {
		go func() {
			if err := DownloadDatabase(targetPath); err == nil {
				mgr.LoadDB(targetPath)
			}
		}()
	}
}
```

- [ ] **Step 3: 运行测试验证通过**

Run: `go test -v ./internal/geoip/...`
Expected: PASS

- [ ] **Step 4: 提交代码**

```bash
git add internal/geoip/downloader.go internal/geoip/downloader_test.go
git commit -m "feat(geoip): add database auto-download and hot reload management"
```

---

### Task 4: 逐跳探测注入 GeoIP 与 ASN (Trace Integration)

**Files:**
- Modify: `internal/probe/types.go`
- Modify: `internal/probe/traceroute.go`
- Test: `internal/probe/traceroute_test.go`

**Interfaces:**
- `HopInfo.GeoLocation string`
- `probe.TraceHopsWithGeo(host string, maxHops int, geoMgr *geoip.Manager) ([]HopInfo, int, error)`

- [ ] **Step 1: 编写测试验证 Hop 注入 Geo 属性**

```go
// internal/probe/traceroute_test.go
func TestTraceHopsGeoAnnotation(t *testing.T) {
	line := " 1  192.168.5.1 (192.168.5.1)  0.785 ms"
	hop, ok := parseTracerouteLine(line)
	if !ok {
		t.Fatalf("failed to parse line")
	}
	mgr := geoip.NewManager("")
	loc := mgr.Lookup(hop.IP)
	hop.Geo = loc.String()
	if !strings.Contains(hop.Geo, "局域网") {
		t.Fatalf("expected 局域网 geo, got %s", hop.Geo)
	}
}
```

- [ ] **Step 2: 更新 `types.go` 与 `traceroute.go`**

在 `HopInfo` 中增加 `Geo string` 和 `ASN string`。
在 `TraceHops` 之后调用 `geoMgr.Lookup(hop.IP)` 补齐地理位置与 ASN。

- [ ] **Step 3: 运行测试验证通过**

Run: `go test -v ./internal/probe/...`
Expected: PASS

- [ ] **Step 4: 提交代码**

```bash
git add internal/probe/types.go internal/probe/traceroute.go internal/probe/traceroute_test.go
git commit -m "feat(probe): annotate trace hops with local geoip and asn"
```

---

### Task 5: TUI 终端渲染与 Snapshot 导出 (TUI & Snapshot)

**Files:**
- Modify: `internal/tui/render.go`
- Modify: `internal/tui/snapshot.go`
- Test: `internal/tui/render_test.go`

- [ ] **Step 1: 格式化下半屏表格为 NextTrace 紧凑排版**

将原 `Host` 列替换为清晰的 `地理位置 & 运营商/AS` 列，保证不折行。
在 `snapshot.go` 导出的 Markdown 报告中，同步输出跳数地理归属。

- [ ] **Step 2: 运行测试验证通过**

Run: `go test -v ./internal/tui/...`
Expected: PASS

- [ ] **Step 3: 提交代码**

```bash
git add internal/tui/render.go internal/tui/snapshot.go internal/tui/render_test.go
git commit -m "feat(tui): render compact geoip and asn column in hop details table"
```

---

### Task 6: CLI 命令行参数与端到端集成 (CLI & Verification)

**Files:**
- Modify: `cmd/routescan/main.go`
- Modify: `Makefile`
- Test: 现场执行真实网络探测

- [x] **Step 1: 支持 `--db` 与 `--update-db` 参数**

- [x] **Step 2: 运行编译与全量单测**

Run: `make test && make build`
Expected: 编译成功，0 错误

- [x] **Step 3: 运行 `./routescan -c` 验证 GeoIP 输出**

Expected: 终端和 `routescan_report.md` 中完整呈现每一跳的 `[局域网]`、运营商及地理归属。

- [x] **Step 4: 提交代码**

```bash
git add cmd/routescan/main.go Makefile
git commit -m "feat(cli): wire geoip flags and complete end-to-end integration"
```
