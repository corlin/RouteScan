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

	cmd := exec.CommandContext(ctx, "traceroute", "-q", "1", "-w", "1", "-m", strconv.Itoa(maxHops), host)
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

	totalHops := len(hops)
	if totalHops == 0 {
		totalHops = 12
	}
	return hops, totalHops, nil
}

// TraceHops traces the network route to a host without requiring root privileges.
// Uses system traceroute with non-privileged flags (-q 1, -w 1).
func TraceHops(host string, maxHops int) ([]HopInfo, int, error) {
	return TraceHopsWithGeo(host, maxHops, nil)
}
