//go:build !windows

package probe

import "os/exec"

func detectSystemEnvironment() *EnvironmentInfo {
	info := &EnvironmentInfo{}
	if out, err := exec.Command("scutil", "--proxy").Output(); err == nil {
		info = parseScutilOutput(string(out))
	}
	if out, err := exec.Command("route", "-n", "get", "default").Output(); err == nil {
		parseRouteOutput(string(out), info)
	}
	if info.GatewayIP == "" {
		info.GatewayIP = findDefaultGatewayFallback()
	}
	return info
}
