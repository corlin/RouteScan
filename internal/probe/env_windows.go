package probe

import (
	"context"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func parseWindowsProxy(enabled bool, server string) *EnvironmentInfo {
	info := &EnvironmentInfo{}
	if !enabled {
		return info
	}
	proxy := strings.TrimSpace(server)
	scheme := "http"
	if strings.Contains(proxy, "=") {
		values := make(map[string]string)
		for _, entry := range strings.Split(proxy, ";") {
			if key, value, ok := strings.Cut(entry, "="); ok {
				values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
			}
		}
		proxy = ""
		for _, protocol := range []string{"https", "http", "socks"} {
			if values[protocol] != "" {
				proxy = values[protocol]
				if protocol == "socks" {
					scheme = "socks5"
				}
				break
			}
		}
	}
	if proxy == "" {
		return info
	}
	if !strings.Contains(proxy, "://") {
		proxy = scheme + "://" + proxy
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Hostname() == "" {
		return info
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return info
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return info
	}
	info.ProxyEnabled, info.ProxyURL = true, proxy
	info.ProxyHost, info.ProxyPort = u.Hostname(), port
	return info
}

func isTunnelInterface(name, address string) bool {
	name = strings.ToLower(name)
	for _, token := range []string{"tun", "tap", "wintun", "clash", "meta", "tailscale", "wireguard"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	ip := net.ParseIP(address).To4()
	return ip != nil && ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

// Only five-column active IPv4 routes qualify; persistent routes have four.
// Numeric columns are the same in localized versions of route.exe.
func parseWindowsRoutes(output string, interfaces map[string]string, info *EnvironmentInfo) {
	bestMetric := int(^uint(0) >> 1)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			continue
		}
		if net.ParseIP(fields[0]) == nil || net.ParseIP(fields[3]) == nil {
			continue
		}
		isTUN := isTunnelInterface(interfaces[fields[3]], fields[3])
		info.HasTUN = info.HasTUN || isTUN
		if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" || isTUN {
			continue
		}
		gateway := net.ParseIP(fields[2])
		if gateway == nil || gateway.IsUnspecified() || gateway.IsLoopback() {
			continue
		}
		metric, err := strconv.Atoi(fields[4])
		if err != nil || metric >= bestMetric {
			continue
		}
		bestMetric = metric
		info.GatewayIP = gateway.String()
		info.ActiveInterface = interfaces[fields[3]]
		if info.ActiveInterface == "" {
			info.ActiveInterface = fields[3]
		}
	}
}

func detectSystemEnvironment() *EnvironmentInfo {
	info := &EnvironmentInfo{}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err == nil {
		enabled, _, _ := key.GetIntegerValue("ProxyEnable")
		server, _, _ := key.GetStringValue("ProxyServer")
		key.Close()
		info = parseWindowsProxy(enabled != 0, server)
	}
	addresses := make(map[string]string)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			addresses[ip.String()] = iface.Name
			info.HasTUN = info.HasTUN || isTunnelInterface(iface.Name, ip.String())
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "route.exe", "print", "-4").Output(); err == nil {
		parseWindowsRoutes(string(out), addresses, info)
	}
	return info
}
