// cmd/routescan/main.go
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"routeScan/internal/geoip"
	"routeScan/internal/probe"
	"routeScan/internal/tui"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// getTargetProxy 决定目标探测所用的代理配置。
// 本地网关严禁走代理，强制直连，防止局域网请求被本地代理客户端丢弃。
func getTargetProxy(t probe.Target, configuredProxy string, env *probe.EnvironmentInfo) string {
	if t.Name == "本地网关" || (env != nil && env.GatewayIP != "" && (t.Host == env.GatewayIP || strings.HasPrefix(t.Host, env.GatewayIP))) {
		return ""
	}
	return configuredProxy
}

func main() {
	// 无论以何种方式退出（按 q、Ctrl+C、异常终止等），均 100% 恢复终端正常键入与回显
	defer tui.RestoreTerminal()

	proxyFlag := flag.String("p", "", "手动指定代理服务器 (如 http://127.0.0.1:7890)")
	intervalFlag := flag.Duration("i", 1500*time.Millisecond, "采样刷新周期")
	directFlag := flag.Bool("d", false, "强制直连模式 (忽略代理)")
	onceFlag := flag.Bool("c", false, "单次诊断模式 (打印报告后退出)")
	outputFlag := flag.String("o", "", "指定诊断报告保存文件路径")
	dbFlag := flag.String("db", "", "自定义本地 MMDB 数据库路径 (默认 ~/.routescan/geoip.mmdb)")
	updateDBFlag := flag.Bool("update-db", false, "强制从开源镜像下载更新本地 MMDB 数据库")
	flag.Parse()

	// 1. 环境感知 (优先感知代理以便加速 GeoIP 下载)
	env := probe.DetectEnvironment()
	if *proxyFlag != "" {
		env.ProxyEnabled = true
		env.ProxyURL = *proxyFlag
	}

	activeProxy := ""
	if !*directFlag && env.ProxyEnabled {
		activeProxy = env.ProxyURL
	}

	// 2. 初始化 GeoIP 引擎
	dbPath := *dbFlag
	if dbPath == "" {
		dbPath = geoip.DefaultDBPath()
	}

	if *updateDBFlag {
		fmt.Printf("正在从开源镜像下载更新本地 MMDB 数据库至: %s ...\n", dbPath)
		if err := geoip.DownloadDatabase(dbPath, activeProxy); err != nil {
			fmt.Fprintf(os.Stderr, "下载数据库失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("GeoIP 数据库下载更新成功！")
		return
	}

	geoMgr := geoip.NewManager(dbPath)
	defer geoMgr.Close()
	geoip.EnsureDatabase(geoMgr, true, activeProxy)

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
				targetProxy := getTargetProxy(t, activeProxy, env)
				snap, _ := probe.MeasureTarget(t, targetProxy)
				traceHost := t.Host
				if h, _, err := net.SplitHostPort(traceHost); err == nil {
					traceHost = h
				}
				hops, totalHops, _ := probe.TraceHopsWithGeo(traceHost, 15, geoMgr)
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

	stopChan := make(chan struct{})
	keyChan := make(chan tui.KeyType, 10)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go tui.ListenKeys(keyChan, stopChan)

	selectedIdx := 0
	isDirect := *directFlag

	ticker := time.NewTicker(*intervalFlag)
	defer ticker.Stop()

	// 探针并发防抖标志
	var isProbing atomic.Bool

	// 探针触发函数（支持并发防抖，防止协程堆积）
	runProbe := func() {
		if !isProbing.CompareAndSwap(false, true) {
			return // 上一次探测尚未完成，跳过本次触发
		}
		go func() {
			defer isProbing.Store(false)
			currentProxy := ""
			if !isDirect && env.ProxyEnabled {
				currentProxy = env.ProxyURL
			}
			var wg sync.WaitGroup
			for _, tgt := range targets {
				wg.Add(1)
				go func(t probe.Target) {
					defer wg.Done()
					targetProxy := getTargetProxy(t, currentProxy, env)
					snap, _ := probe.MeasureTarget(t, targetProxy)
					state.Update(t.Name, snap)
				}(tgt)
			}
			wg.Wait()
		}()
	}

	// 真实后台逐跳路由探测（异步执行，带防重叠锁）
	var traceInProgress sync.Map
	triggerTrace := func(t probe.Target) {
		if _, loaded := traceInProgress.LoadOrStore(t.Name, true); loaded {
			return
		}
		go func(target probe.Target) {
			defer traceInProgress.Delete(target.Name)
			traceHost := target.Host
			if h, _, err := net.SplitHostPort(traceHost); err == nil {
				traceHost = h
			}
			hops, totalHops, err := probe.TraceHopsWithGeo(traceHost, 15, geoMgr)
			if err == nil && len(hops) > 0 {
				state.UpdateHops(target.Name, hops, totalHops)
			}
		}(t)
	}

	// 首次立即探测与初始后台逐跳路由追踪
	runProbe()
	for _, tgt := range targets {
		triggerTrace(tgt)
	}
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
					triggerTrace(targets[selectedIdx])
				}
			case tui.KeyDown:
				if selectedIdx < len(targets)-1 {
					selectedIdx++
					triggerTrace(targets[selectedIdx])
				}
			case tui.KeyProxyToggle:
				isDirect = !isDirect
				runProbe()
			case tui.KeyRefresh:
				runProbe()
				triggerTrace(targets[selectedIdx])
			case tui.KeySnapshot:
				tui.ExportSnapshot("routescan_snapshot.md", targets, state, env)
			}
			fmt.Print(tui.RenderDashboard(targets, state, selectedIdx, env, isDirect))

		case <-ticker.C:
			runProbe()
			if curSnap := state.Get(targets[selectedIdx].Name); curSnap == nil || len(curSnap.HopsList) == 0 {
				triggerTrace(targets[selectedIdx])
			}
			fmt.Print(tui.RenderDashboard(targets, state, selectedIdx, env, isDirect))
		}
	}
}
