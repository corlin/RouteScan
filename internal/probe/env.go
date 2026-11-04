package probe

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// EnvironmentInfo holds information about local network environment and proxy settings.
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

// DetectEnvironment inspects the local macOS network environment,
// reading system proxy settings, environment variables, default gateway and interfaces.
func DetectEnvironment() *EnvironmentInfo {
	info := &EnvironmentInfo{}

	// 1. 探测 macOS 系统代理 (scutil --proxy)
	cmd := exec.Command("scutil", "--proxy")
	if out, err := cmd.Output(); err == nil {
		parsed := parseScutilOutput(string(out))
		info.ProxyEnabled = parsed.ProxyEnabled
		info.ProxyURL = parsed.ProxyURL
		info.ProxyHost = parsed.ProxyHost
		info.ProxyPort = parsed.ProxyPort
	}

	// 环境变量兜底 (http_proxy / https_proxy / all_proxy)
	resolveEnvProxyFallback(info)

	// 2. 探测网关与网卡 (route -n get default)
	routeCmd := exec.Command("route", "-n", "get", "default")
	if out, err := routeCmd.Output(); err == nil {
		parseRouteOutput(string(out), info)
	}

	if info.GatewayIP == "" {
		// 局域网默认兜底查找
		info.GatewayIP = findDefaultGatewayFallback()
	}

	return info
}

// parseScutilOutput extracts proxy configurations from macOS `scutil --proxy` output.
func parseScutilOutput(out string) *EnvironmentInfo {
	info := &EnvironmentInfo{}
	httpEnabled := strings.Contains(out, "HTTPEnable : 1")
	httpsEnabled := strings.Contains(out, "HTTPSEnable : 1")
	socksEnabled := strings.Contains(out, "SOCKSEnable : 1")

	reHTTPHost := regexp.MustCompile(`HTTPProxy\s*:\s*([^\s]+)`)
	reHTTPPort := regexp.MustCompile(`HTTPPort\s*:\s*([0-9]+)`)
	reHTTPSHost := regexp.MustCompile(`HTTPSProxy\s*:\s*([^\s]+)`)
	reHTTPSPort := regexp.MustCompile(`HTTPSPort\s*:\s*([0-9]+)`)
	reSOCKSHost := regexp.MustCompile(`SOCKSProxy\s*:\s*([^\s]+)`)
	reSOCKSPort := regexp.MustCompile(`SOCKSPort\s*:\s*([0-9]+)`)

	if httpEnabled {
		hMatch := reHTTPHost.FindStringSubmatch(out)
		pMatch := reHTTPPort.FindStringSubmatch(out)
		if len(hMatch) > 1 && len(pMatch) > 1 {
			info.ProxyEnabled = true
			info.ProxyHost = hMatch[1]
			port, _ := strconv.Atoi(pMatch[1])
			info.ProxyPort = port
			info.ProxyURL = "http://" + net.JoinHostPort(info.ProxyHost, strconv.Itoa(info.ProxyPort))
			return info
		}
	}

	if httpsEnabled {
		hMatch := reHTTPSHost.FindStringSubmatch(out)
		pMatch := reHTTPSPort.FindStringSubmatch(out)
		if len(hMatch) > 1 && len(pMatch) > 1 {
			info.ProxyEnabled = true
			info.ProxyHost = hMatch[1]
			port, _ := strconv.Atoi(pMatch[1])
			info.ProxyPort = port
			info.ProxyURL = "http://" + net.JoinHostPort(info.ProxyHost, strconv.Itoa(info.ProxyPort))
			return info
		}
	}

	if socksEnabled {
		hMatch := reSOCKSHost.FindStringSubmatch(out)
		pMatch := reSOCKSPort.FindStringSubmatch(out)
		if len(hMatch) > 1 && len(pMatch) > 1 {
			info.ProxyEnabled = true
			info.ProxyHost = hMatch[1]
			port, _ := strconv.Atoi(pMatch[1])
			info.ProxyPort = port
			info.ProxyURL = "socks5://" + net.JoinHostPort(info.ProxyHost, strconv.Itoa(info.ProxyPort))
			return info
		}
	}

	return info
}

// resolveEnvProxyFallback checks common environment variables when system proxy is not enabled.
func resolveEnvProxyFallback(info *EnvironmentInfo) {
	if info.ProxyEnabled {
		return
	}

	envVars := []string{
		"https_proxy", "HTTPS_PROXY",
		"http_proxy", "HTTP_PROXY",
		"all_proxy", "ALL_PROXY",
	}

	for _, k := range envVars {
		if val := os.Getenv(k); val != "" {
			info.ProxyEnabled = true
			info.ProxyURL = val

			target := val
			if !strings.Contains(target, "://") {
				target = "http://" + target
			}
			if u, err := url.Parse(target); err == nil {
				info.ProxyHost = u.Hostname()
				if p, err := strconv.Atoi(u.Port()); err == nil {
					info.ProxyPort = p
				}
			}
			return
		}
	}
}

// parseRouteOutput parses stdout of `route -n get default` to extract gateway and interface.
func parseRouteOutput(out string, info *EnvironmentInfo) {
	scanner := bufio.NewScanner(strings.NewReader(out))
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

// findDefaultGatewayFallback discovers a plausible router gateway address (e.g. x.x.x.1).
func findDefaultGatewayFallback() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
				continue
			}
			if strings.HasPrefix(iface.Name, "en") {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, a := range addrs {
					if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ip := ipnet.IP.To4(); ip != nil {
							return net.IPv4(ip[0], ip[1], ip[2], 1).String()
						}
					}
				}
			}
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.To4()
				return net.IPv4(ip[0], ip[1], ip[2], 1).String()
			}
		}
	}
	return "127.0.0.1"
}
