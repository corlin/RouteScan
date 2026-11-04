// cmd/routescan/main.go
package main

import (
	"flag"
	"fmt"
	"net"
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
				traceHost := t.Host
				if h, _, err := net.SplitHostPort(traceHost); err == nil {
					traceHost = h
				}
				hops, totalHops, _ := probe.TraceHops(traceHost, 15)
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

	// 首次立即探测并初始渲染
	runProbe()
	fmt.Print(tui.RenderDashboard(targets, state, selectedIdx, env, isDirect))

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
