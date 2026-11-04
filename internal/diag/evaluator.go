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
	isGateway := snap.Target.Name == "本地网关" || (env != nil && env.GatewayIP != "" && snap.Target.Host == env.GatewayIP)
	if isGateway {
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
	// 在代理环境中，snap.TCP 仅代表到本地代理客户端的握手（通常 <1ms），真实的端到端跨洋网络 RTT 体现在 snap.TLS。
	effectiveRTT := snap.TCP
	if (env != nil && env.ProxyEnabled) || snap.Target.IsProxy || snap.TLS > 0 {
		if snap.TLS > effectiveRTT {
			effectiveRTT = snap.TLS
		}
	}

	if effectiveRTT > MaxUSTCPRTT || snap.TLS > MaxTLSLatency {
		return &Diagnosis{
			Level:          LevelWarning,
			StatusDesc:     "跨洋线路拥塞或绕路",
			Bottleneck:     "跨国骨干海缆 / BGP 路由绕路",
			Breakdown:      fmt.Sprintf("有效网络握手耗时 %v (TCP: %v, TLS: %v, 超出基准)", effectiveRTT, snap.TCP, snap.TLS),
			Recommendation: "代理节点路由可能绕道欧洲或海缆高峰期拥堵，建议切换节点至香港/日本/美西优化线路。",
		}
	}

	// 4. 服务端排队与推理延迟 (TTFB) 瓶颈分析
	// 净服务端排队处理耗时应剔除网络握手层耗时
	serverProcTime := snap.TTFB - snap.TotalHandshake()
	if serverProcTime > SevereServerQueue && effectiveRTT <= MaxUSTCPRTT && snap.TLS <= MaxTLSLatency {
		return &Diagnosis{
			Level:          LevelNormal,
			StatusDesc:     "网络通畅，服务端排队",
			Bottleneck:     "官方服务端/模型推理排队",
			Breakdown:      fmt.Sprintf("网络握手仅 %v (TCP: %v, TLS: %v)，净服务端处理耗时 %v", snap.TotalHandshake(), snap.TCP, snap.TLS, serverProcTime),
			Recommendation: "当前网络链路极好，卡顿系官方 API 负载过高或正在思考，属正常应用层耗时。",
		}
	}

	return &Diagnosis{
		Level:          LevelOptimal,
		StatusDesc:     "链路极佳",
		Bottleneck:     "全链路正常无卡顿",
		Breakdown:      fmt.Sprintf("TCP: %v | TLS: %v | TTFB: %v", snap.TCP, snap.TLS, snap.TTFB),
		Recommendation: "当前网络与服务状态处于最佳响应区间。",
	}
}
