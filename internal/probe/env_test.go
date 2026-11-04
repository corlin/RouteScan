package probe

import (
	"net"
	"os"
	"testing"
)

func TestParseScutilProxy(t *testing.T) {
	sampleOutput := `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
}`
	info := parseScutilOutput(sampleOutput)
	if !info.ProxyEnabled || info.ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("unexpected proxy parsed: %+v", info)
	}
	if info.ProxyHost != "127.0.0.1" || info.ProxyPort != 7890 {
		t.Fatalf("unexpected proxy host/port: host=%s port=%d", info.ProxyHost, info.ProxyPort)
	}
}

func TestParseScutilProxyDisabled(t *testing.T) {
	sampleOutput := `<dictionary> {
  HTTPEnable : 0
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 0
}`
	info := parseScutilOutput(sampleOutput)
	if info.ProxyEnabled {
		t.Fatalf("expected proxy disabled, got %+v", info)
	}
	if info.ProxyURL != "" {
		t.Fatalf("expected empty ProxyURL, got %s", info.ProxyURL)
	}
}

func TestParseScutilProxySocks(t *testing.T) {
	sampleOutput := `<dictionary> {
  HTTPEnable : 0
  HTTPSEnable : 0
  SOCKSEnable : 1
  SOCKSPort : 10808
  SOCKSProxy : 127.0.0.1
}`
	info := parseScutilOutput(sampleOutput)
	if !info.ProxyEnabled || info.ProxyURL != "socks5://127.0.0.1:10808" {
		t.Fatalf("unexpected socks proxy parsed: %+v", info)
	}
}

func TestParseRouteOutputGateway(t *testing.T) {
	sampleOutput := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0`

	info := &EnvironmentInfo{}
	parseRouteOutput(sampleOutput, info)

	if info.GatewayIP != "192.168.1.1" {
		t.Fatalf("expected GatewayIP 192.168.1.1, got %q", info.GatewayIP)
	}
	if info.ActiveInterface != "en0" {
		t.Fatalf("expected ActiveInterface en0, got %q", info.ActiveInterface)
	}
	if info.HasTUN {
		t.Fatalf("expected HasTUN=false for en0, got true")
	}
}

func TestParseRouteOutputTUN(t *testing.T) {
	sampleOutput := `   route to: default
destination: default
       mask: default
  interface: utun4
      flags: <UP,DONE,CLONING,STATIC,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      4000         0`

	info := &EnvironmentInfo{}
	parseRouteOutput(sampleOutput, info)

	if info.ActiveInterface != "utun4" {
		t.Fatalf("expected ActiveInterface utun4, got %q", info.ActiveInterface)
	}
	if !info.HasTUN {
		t.Fatalf("expected HasTUN=true for utun4, got false")
	}
}

func TestFindDefaultGatewayFallback(t *testing.T) {
	gw := findDefaultGatewayFallback()
	if gw == "" {
		t.Fatalf("expected non-empty gateway fallback")
	}
	ip := net.ParseIP(gw)
	if ip == nil {
		t.Fatalf("expected valid IP address, got %q", gw)
	}
}

func TestDetectEnvironment(t *testing.T) {
	info := DetectEnvironment()
	if info == nil {
		t.Fatalf("expected non-nil EnvironmentInfo")
	}
	// Verify that at least GatewayIP is fallback or detected
	if info.GatewayIP == "" {
		t.Fatalf("expected non-empty GatewayIP")
	}
}

func TestDetectEnvironmentEnvFallback(t *testing.T) {
	// Test environment variable parsing logic
	origHTTP := os.Getenv("http_proxy")
	origHTTPS := os.Getenv("https_proxy")
	origALL := os.Getenv("all_proxy")
	defer func() {
		os.Setenv("http_proxy", origHTTP)
		os.Setenv("https_proxy", origHTTPS)
		os.Setenv("all_proxy", origALL)
	}()

	os.Setenv("http_proxy", "")
	os.Setenv("all_proxy", "")
	os.Setenv("https_proxy", "http://127.0.0.1:9999")

	info := &EnvironmentInfo{}
	resolveEnvProxyFallback(info)
	if !info.ProxyEnabled || info.ProxyURL != "http://127.0.0.1:9999" {
		t.Fatalf("expected proxy enabled from https_proxy, got %+v", info)
	}
	if info.ProxyHost != "127.0.0.1" || info.ProxyPort != 9999 {
		t.Fatalf("expected host 127.0.0.1 and port 9999, got host=%s port=%d", info.ProxyHost, info.ProxyPort)
	}
}
