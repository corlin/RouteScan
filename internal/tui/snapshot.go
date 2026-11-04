// internal/tui/snapshot.go
package tui

import (
	"fmt"
	"os"
	"routeScan/internal/diag"
	"routeScan/internal/probe"
	"time"
)

// ExportSnapshot writes a complete diagnostic markdown report to the specified file path.
func ExportSnapshot(path string, targets []probe.Target, state *probe.StateManager, env *probe.EnvironmentInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := "-"
	proxyEnabled := false
	proxyURL := "-"
	if env != nil {
		gw = env.GatewayIP
		proxyEnabled = env.ProxyEnabled
		proxyURL = env.ProxyURL
	}

	fmt.Fprintf(f, "# RouteScan 网络与 AI 服务延迟体检报告\n\n")
	fmt.Fprintf(f, "- **生成时间**: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "- **本地网关**: %s\n", gw)
	fmt.Fprintf(f, "- **代理环境**: %t (URL: %s)\n\n", proxyEnabled, proxyURL)
	fmt.Fprintf(f, "## 1. 核心目标耗时对比表\n\n")
	fmt.Fprintf(f, "| 服务名称 | 路由跳数 | DNS(ms) | TCP RTT(ms) | TLS(ms) | TTFB(ms) | 丢包率 | 综合状态 |\n")
	fmt.Fprintf(f, "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, tgt := range targets {
		if state == nil {
			continue
		}
		snap := state.Get(tgt.Name)
		if snap == nil {
			continue
		}
		d := diag.Evaluate(snap, env)
		fmt.Fprintf(f, "| %s | %d | %d | %d | %d | %d | %.1f%% | %s |\n",
			tgt.Name, snap.Hops, snap.DNS.Milliseconds(), snap.TCP.Milliseconds(),
			snap.TLS.Milliseconds(), snap.TTFB.Milliseconds(), snap.PacketLoss, d.Level)
	}

	fmt.Fprintf(f, "\n## 2. CCIE 专家诊断与瓶颈分析\n\n")
	for _, tgt := range targets {
		var snap *probe.ProbeSnapshot
		if state != nil {
			snap = state.Get(tgt.Name)
		}
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
