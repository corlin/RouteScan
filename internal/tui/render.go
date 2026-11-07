// internal/tui/render.go
package tui

import (
	"fmt"
	"routeScan/internal/diag"
	"routeScan/internal/probe"
	"strings"
	"time"
)

type Dashboard struct {
	Targets     []probe.Target
	State       *probe.StateManager
	SelectedIdx int
	Env         *probe.EnvironmentInfo
	IsDirect    bool
}

func NewDashboard(targets []probe.Target, state *probe.StateManager, env *probe.EnvironmentInfo) *Dashboard {
	return &Dashboard{
		Targets: targets,
		State:   state,
		Env:     env,
	}
}

func (d *Dashboard) Render() string {
	return RenderDashboard(d.Targets, d.State, d.SelectedIdx, d.Env, d.IsDirect)
}

// Render is a convenience wrapper for RenderDashboard.
func Render(targets []probe.Target, state *probe.StateManager, selectedIdx int, env *probe.EnvironmentInfo, isDirect bool) string {
	return RenderDashboard(targets, state, selectedIdx, env, isDirect)
}

func runeWidth(r rune) int {
	if r >= 0x1100 &&
		(r <= 0x115f ||
			r == 0x2329 || r == 0x232a ||
			(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
			(r >= 0xac00 && r <= 0xd7a3) ||
			(r >= 0xf900 && r <= 0xfaff) ||
			(r >= 0xfe10 && r <= 0xfe19) ||
			(r >= 0xfe30 && r <= 0xfe6f) ||
			(r >= 0xff00 && r <= 0xff60) ||
			(r >= 0xffe0 && r <= 0xffe6) ||
			(r >= 0x20000 && r <= 0x2fffd) ||
			(r >= 0x30000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}

func stringDisplayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func formatColumn(s string, targetWidth int) string {
	curW := stringDisplayWidth(s)
	if curW == targetWidth {
		return s
	}
	if curW < targetWidth {
		return s + strings.Repeat(" ", targetWidth-curW)
	}
	runes := []rune(s)
	var sb strings.Builder
	accW := 0
	for _, r := range runes {
		rw := runeWidth(r)
		if accW+rw+2 > targetWidth {
			sb.WriteString("..")
			accW += 2
			break
		}
		sb.WriteRune(r)
		accW += rw
	}
	if accW < targetWidth {
		sb.WriteString(strings.Repeat(" ", targetWidth-accW))
	}
	return sb.String()
}

func formatTableRow(snap *probe.ProbeSnapshot, isSelected bool, env ...*probe.EnvironmentInfo) string {
	cursor := "  "
	if isSelected {
		cursor = "> "
	}
	if snap == nil || snap.Target.URL == "" {
		name := "Target"
		if snap != nil && snap.Target.Name != "" {
			name = snap.Target.Name
		}
		return fmt.Sprintf("%s%s  (等待初次采样...)", cursor, formatColumn(name, 18))
	}

	hopsStr := fmt.Sprintf("%d", snap.Hops)
	if snap.Hops <= 0 {
		hopsStr = "-"
	}

	var curEnv *probe.EnvironmentInfo
	if len(env) > 0 {
		curEnv = env[0]
	}

	d := diag.Evaluate(snap, curEnv)
	statusStr := string(d.Level)

	return fmt.Sprintf("%s%s %5s %8s %9s %8s %9s %7.1f%% %7s %8s",
		cursor,
		formatColumn(snap.Target.Name, 18),
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
	gatewayIP := "-"
	hasTUN := false
	egressIP := "-"
	if env != nil {
		gatewayIP = env.GatewayIP
		hasTUN = env.HasTUN
		ip, _ := env.GetEgress()
		if ip != "" {
			egressIP = ip
		}
		if !isDirect && env.ProxyEnabled {
			modeStr = fmt.Sprintf("代理模式 [%s]", env.ProxyURL)
		}
	}

	sb.WriteString("\033[H") // 回到光标起始 (0,0)
	sb.WriteString(fmt.Sprintf("\033[1;36m╔═══════════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\033[K\n"))
	sb.WriteString(fmt.Sprintf("\033[1;36m║  RouteScan v1.0 - CCIE Multi-Path & AI Latency Inspector      %-31s ║\033[0m\033[K\n", modeStr))
	if !isDirect && env != nil && env.ProxyEnabled && egressIP != "-" {
		sb.WriteString(fmt.Sprintf("\033[1;36m║  本地网关: %-15s (TUN: %-5t) | 出海节点: %-15s | 采样时间: %-8s   ║\033[0m\033[K\n", gatewayIP, hasTUN, egressIP, time.Now().Format("15:04:05")))
	} else {
		sb.WriteString(fmt.Sprintf("\033[1;36m║  本地网关: %-15s (TUN: %-5t) | 采样时间: %-22s       ║\033[0m\033[K\n", gatewayIP, hasTUN, time.Now().Format("15:04:05")))
	}
	sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\033[K\n"))
	sb.WriteString(fmt.Sprintf("\033[1;37m   目标服务             跳数    DNS       TCP RTT     TLS      TTFB   丢包率    抖动     状态    \033[0m\033[K\n"))

	for i, tgt := range targets {
		var snap *probe.ProbeSnapshot
		if state != nil {
			snap = state.Get(tgt.Name)
		}
		row := formatTableRow(snap, i == selectedIdx, env)
		if i == selectedIdx {
			sb.WriteString(fmt.Sprintf("\033[1;32m%s\033[0m\033[K\n", row))
		} else {
			sb.WriteString(fmt.Sprintf("%s\033[K\n", row))
		}
	}

	sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\033[K\n"))
	sb.WriteString(fmt.Sprintf("\033[1;33m【CCIE 专家实时诊断与瓶颈归因】\033[0m\033[K\n"))

	if len(targets) > 0 {
		if selectedIdx < 0 || selectedIdx >= len(targets) {
			selectedIdx = 0
		}
		curTarget := targets[selectedIdx]
		var curSnap *probe.ProbeSnapshot
		if state != nil {
			curSnap = state.Get(curTarget.Name)
		}
		d := diag.Evaluate(curSnap, env)

		sb.WriteString(fmt.Sprintf(" 聚焦目标: \033[1;37m%-16s (%s)\033[0m\033[K\n", curTarget.Name, curTarget.URL))
		sb.WriteString(fmt.Sprintf(" 状态评估: \033[1;32m%s\033[0m | 瓶颈归因: \033[1;31m%s\033[0m\033[K\n", d.StatusDesc, d.Bottleneck))
		sb.WriteString(fmt.Sprintf(" 指标拆解: %s\033[K\n", d.Breakdown))
		if d.Recommendation != "" {
			sb.WriteString(fmt.Sprintf(" 专家建议: \033[0;33m%s\033[0m\033[K\n", d.Recommendation))
		}

		sb.WriteString(fmt.Sprintf("\033[1;36m╠═══════════════════════════════════════════════════════════════════════════════════════════════╣\033[0m\033[K\n"))
		sb.WriteString(fmt.Sprintf("\033[1;35m【逐跳路由明细: %s】 (按 ↑/↓ 切换目标)\033[0m\033[K\n", curTarget.Name))
		if curSnap != nil && curSnap.Target.IsProxy {
			sb.WriteString("   代理逻辑拓扑：包含估算节点与耗时，非 ICMP 逐跳实测。\033[K\n")
		}
		if curSnap != nil && curSnap.TraceErr != nil {
			sb.WriteString(fmt.Sprintf("   路由追踪未完成: %v\033[K\n", curSnap.TraceErr))
		}
		sb.WriteString(fmt.Sprintf("  跳数   IP 地址           地理位置 & 运营商/AS                          第1次     第2次     丢包率\033[K\n"))

		if curSnap != nil && len(curSnap.HopsList) > 0 {
			for _, h := range curSnap.HopsList {
				geoInfo := h.Geo
				if geoInfo == "" {
					geoInfo = h.Host
				}
				sb.WriteString(fmt.Sprintf("   %-3d   %-16s  %s %8s  %8s   %5.1f%%\033[K\n",
					h.HopNum, h.IP, formatColumn(geoInfo, 38), formatDuration(h.RTT1), formatDuration(h.RTT2), h.Loss))
			}
		} else {
			sb.WriteString("   暂无逐跳探测数据；探测未完成或网络未返回 ICMP 响应。\033[K\n")
		}
	}

	sb.WriteString(fmt.Sprintf("\033[1;36m╚═══════════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\033[K\n"))
	sb.WriteString(fmt.Sprintf("\033[0;37m[↑/↓] 切换目标  [p] 代理/直连切换  [r] 立即重测  [s] 保存快照  [q] 退出\033[0m\033[K\n"))
	sb.WriteString("\033[J") // 清除光标下方剩余旧内容，彻底杜绝残影

	return sb.String()
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}
