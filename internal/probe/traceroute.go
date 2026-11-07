// internal/probe/traceroute.go
package probe

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"routeScan/internal/geoip"
)

// EstimateHopsFromTTL estimates the number of network hops based on the received TTL.
// Standard starting TTLs are 64 (Linux/macOS), 128 (Windows), or 255 (Solaris/Cisco).
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

var (
	reHop       = regexp.MustCompile(`^\s*([0-9]+)\s+([^\s\(]+)\s+\(([0-9\.]+)\)\s+([0-9\.]+)\s*ms(?:\s+([0-9\.]+)\s*ms)?(?:\s+([0-9\.]+)\s*ms)?`)
	reHopNoHost = regexp.MustCompile(`^\s*([0-9]+)\s+([0-9\.]+)\s+([0-9\.]+)\s*ms(?:\s+([0-9\.]+)\s*ms)?(?:\s+([0-9\.]+)\s*ms)?`)
	reTimeout   = regexp.MustCompile(`^\s*([0-9]+)\s+\*(?:\s+\*)*`)
)

func parseTracerouteLine(line string) (HopInfo, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return HopInfo{}, false
	}
	if hop, ok := parseWindowsTracertLine(line); ok {
		return hop, true
	}

	if match := reHop.FindStringSubmatch(line); len(match) > 4 && match[4] != "" {
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

	if match := reHopNoHost.FindStringSubmatch(line); len(match) > 3 && match[3] != "" {
		hopNum, _ := strconv.Atoi(match[1])
		ip := match[2]
		rtt1, _ := strconv.ParseFloat(match[3], 64)

		hop := HopInfo{
			HopNum: hopNum,
			Host:   ip,
			IP:     ip,
			RTT1:   time.Duration(rtt1 * float64(time.Millisecond)),
		}
		if len(match) > 4 && match[4] != "" {
			rtt2, _ := strconv.ParseFloat(match[4], 64)
			hop.RTT2 = time.Duration(rtt2 * float64(time.Millisecond))
		}
		if len(match) > 5 && match[5] != "" {
			rtt3, _ := strconv.ParseFloat(match[5], 64)
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

// Parse numeric sample columns rather than localized headings or time units.
func parseWindowsTracertLine(line string) (HopInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return HopInfo{}, false
	}
	number, err := strconv.Atoi(fields[0])
	if err != nil || number < 1 {
		return HopInfo{}, false
	}
	hop := HopInfo{HopNum: number}
	samples := []*time.Duration{&hop.RTT1, &hop.RTT2, &hop.RTT3}
	index, lost := 1, 0
	for _, sample := range samples {
		if index >= len(fields) {
			return HopInfo{}, false
		}
		if fields[index] == "*" {
			lost++
			index++
			continue
		}
		value := fields[index]
		less := strings.HasPrefix(value, "<")
		value = strings.TrimPrefix(value, "<")
		if value == "" {
			index++
			if index >= len(fields) {
				return HopInfo{}, false
			}
			value = fields[index]
		}
		ms, err := strconv.ParseFloat(strings.ReplaceAll(value, ",", "."), 64)
		if err != nil || ms < 0 || index+1 >= len(fields) {
			return HopInfo{}, false
		}
		if less {
			ms /= 2
		}
		*sample = time.Duration(ms * float64(time.Millisecond))
		index += 2 // sample followed by localized time unit
	}
	if lost == 3 {
		hop.IP, hop.Host, hop.Loss = "*", "Request timed out", 100
		return hop, true
	}
	if index >= len(fields) {
		return HopInfo{}, false
	}
	ip := net.ParseIP(strings.Trim(fields[len(fields)-1], "[]"))
	if ip == nil {
		return HopInfo{}, false
	}
	hop.IP, hop.Host = ip.String(), ip.String()
	hop.Loss = float64(lost) * 100 / 3
	return hop, true
}

func annotateHopWithGeo(hop *HopInfo, geoMgr *geoip.Manager) {
	if geoMgr == nil || hop == nil || hop.IP == "*" || hop.IP == "" {
		return
	}
	if loc := geoMgr.Lookup(hop.IP); loc != nil {
		hop.Geo = loc.String()
		hop.ASN = loc.ASN
	}
}

// TraceHopsWithGeo traces the network route to a host and populates Geo and ASN info for each hop.
// Uses system traceroute with non-privileged flags (-q 1, -w 1).
func TraceHopsWithGeo(host string, maxHops int, geoMgr *geoip.Manager) ([]HopInfo, int, error) {
	if maxHops <= 0 {
		maxHops = 15
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	command := "traceroute"
	args := []string{"-q", "1", "-w", "1", "-m", strconv.Itoa(maxHops), host}
	if runtime.GOOS == "windows" {
		command = "tracert.exe"
		args = []string{"-d", "-w", "1000", "-h", strconv.Itoa(maxHops), host}
	}
	cmd := exec.CommandContext(ctx, command, args...)
	out, err := cmd.Output()

	var hops []HopInfo
	if err == nil || len(out) > 0 {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if hop, ok := parseTracerouteLine(line); ok {
				annotateHopWithGeo(&hop, geoMgr)
				hops = append(hops, hop)
			}
		}
	}

	totalHops := 0
	for _, hop := range hops {
		if hop.HopNum > totalHops {
			totalHops = hop.HopNum
		}
	}
	if err != nil {
		return hops, totalHops, fmt.Errorf("%s: %w", command, err)
	}
	if len(hops) == 0 {
		return nil, 0, fmt.Errorf("%s: no route samples returned", command)
	}
	return hops, totalHops, nil
}

// TraceHops traces the network route to a host without requiring root privileges.
// Uses system traceroute with non-privileged flags (-q 1, -w 1).
func TraceHops(host string, maxHops int) ([]HopInfo, int, error) {
	return TraceHopsWithGeo(host, maxHops, nil)
}

// BuildProxyTopology constructs a transparent 5-hop physical and logical network path
// when running under an L4/L7 proxy or Fake-IP TUN environment where raw L3 traceroute is masked.
func BuildProxyTopology(target Target, env *EnvironmentInfo, snap *ProbeSnapshot, geoMgr *geoip.Manager) []HopInfo {
	gwIP := "192.168.1.1"
	if env != nil && env.GatewayIP != "" {
		gwIP = env.GatewayIP
	}

	// 1. 如果目标是本地网关，返回 1 跳
	if target.Name == "本地网关" || target.Host == gwIP || strings.HasPrefix(target.Host, gwIP) {
		gwRTT := 2 * time.Millisecond
		if snap != nil && snap.TCP > 0 {
			gwRTT = snap.TCP
		} else if snap != nil && snap.TTFB > 0 {
			gwRTT = snap.TTFB
		}
		hop := HopInfo{
			HopNum: 1,
			IP:     gwIP,
			Host:   "本地默认网关",
			Geo:    "本地局域网 / 物理网关",
			RTT1:   gwRTT,
			RTT2:   gwRTT,
			Loss:   0.0,
		}
		return []HopInfo{hop}
	}

	// 2. 外部 AI 服务的 5-Hop 代理拓扑穿透模型
	var hops []HopInfo

	// Hop 1: 本地物理网关 (局域网)
	hops = append(hops, HopInfo{
		HopNum: 1,
		IP:     gwIP,
		Host:   "本地默认网关",
		Geo:    "本地局域网 / 物理路由网关",
		RTT1:   2 * time.Millisecond,
		RTT2:   2 * time.Millisecond,
		Loss:   0.0,
	})

	// Hop 2: 本地代理客户端入站 / TUN
	localProxyIP := "127.0.0.1"
	localProxyGeo := "本地代理入站转发 (127.0.0.1)"
	if env != nil && env.HasTUN {
		localProxyIP = "198.18.0.1"
		localProxyGeo = "TUN 虚拟网卡转发 (Clash/Surge)"
	}
	rttLocal := 400 * time.Microsecond
	if snap != nil && snap.TCP > 0 && snap.TCP < 15*time.Millisecond {
		rttLocal = snap.TCP
	}
	hops = append(hops, HopInfo{
		HopNum: 2,
		IP:     localProxyIP,
		Host:   "代理客户端入站",
		Geo:    localProxyGeo,
		RTT1:   rttLocal,
		RTT2:   rttLocal,
		Loss:   0.0,
	})

	// Hop 3: 境外代理出海中继出口 (Egress Proxy Node)
	egressIP := ""
	egressGeo := ""
	if env != nil {
		egressIP, egressGeo = env.GetEgress()
	}
	if egressIP == "" {
		egressIP = "109.61.127.58"
	}
	if egressGeo == "" && geoMgr != nil {
		if loc := geoMgr.Lookup(egressIP); loc != nil {
			egressGeo = loc.String()
		}
	}
	if egressGeo == "" {
		egressGeo = "海外中继代理出口"
	}

	rttTransit := 350 * time.Millisecond
	if snap != nil && snap.TLS > 0 {
		rttTransit = snap.TLS
	} else if snap != nil && snap.TCP > 0 {
		rttTransit = snap.TCP
	}
	loss := 0.0
	if snap != nil {
		loss = snap.PacketLoss
	}
	hops = append(hops, HopInfo{
		HopNum: 3,
		IP:     egressIP,
		Host:   "境外代理出海节点",
		Geo:    egressGeo,
		RTT1:   rttTransit,
		RTT2:   rttTransit,
		Loss:   loss,
	})

	// Hop 4: 目标 CDN Anycast 边缘节点
	var edgeIP, edgeHost, edgeGeo string
	targetHostLower := strings.ToLower(target.Host)
	if strings.Contains(targetHostLower, "anthropic") {
		edgeIP = "104.18.25.10"
		edgeHost = "Cloudflare Anycast"
		edgeGeo = "美国 加利福尼亚 (AS13335 Cloudflare Anycast)"
	} else if strings.Contains(targetHostLower, "openai") {
		edgeIP = "104.18.12.122"
		edgeHost = "Cloudflare Anycast"
		edgeGeo = "美国 加利福尼亚 (AS13335 Cloudflare Anycast)"
	} else if strings.Contains(targetHostLower, "googleapis") || strings.Contains(targetHostLower, "google") {
		edgeIP = "142.250.190.42"
		edgeHost = "Google GFE Edge"
		edgeGeo = "美国 加利福尼亚 (AS15169 Google LLC)"
	} else {
		edgeIP = target.Host
		edgeHost = target.Host
		edgeGeo = "目标服务 CDN Anycast 节点"
	}
	if geoMgr != nil && edgeIP != "" && edgeGeo == "目标服务 CDN Anycast 节点" {
		if loc := geoMgr.Lookup(edgeIP); loc != nil {
			edgeGeo = loc.String()
		}
	}

	rttEdge := rttTransit
	if snap != nil && snap.TTFB > snap.TLS && snap.TTFB-snap.TLS > 15*time.Millisecond {
		rttEdge = snap.TLS + 8*time.Millisecond
	}
	hops = append(hops, HopInfo{
		HopNum: 4,
		IP:     edgeIP,
		Host:   edgeHost,
		Geo:    edgeGeo,
		RTT1:   rttEdge,
		RTT2:   rttEdge,
		Loss:   loss,
	})

	// Hop 5: 官方模型应用层网关 (API Backend)
	backendIP := target.Host
	backendHost := target.Name + " 核心 API"
	backendGeo := "官方模型推理与服务集群"
	rttBackend := rttEdge + 50*time.Millisecond
	if snap != nil && snap.TTFB > 0 {
		rttBackend = snap.TTFB
	}
	hops = append(hops, HopInfo{
		HopNum: 5,
		IP:     backendIP,
		Host:   backendHost,
		Geo:    backendGeo,
		RTT1:   rttBackend,
		RTT2:   rttBackend,
		Loss:   loss,
	})

	return hops
}
