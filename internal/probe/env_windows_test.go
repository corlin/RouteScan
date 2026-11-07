package probe

import "testing"

func TestWindowsProxySettings(t *testing.T) {
	for _, tc := range []struct {
		server, want string
		enabled      bool
	}{
		{"127.0.0.1:7890", "http://127.0.0.1:7890", true},
		{"http=127.0.0.1:8080;https=127.0.0.1:7890;socks=127.0.0.1:1080", "http://127.0.0.1:7890", true},
		{"socks=127.0.0.1:1080", "socks5://127.0.0.1:1080", true},
		{"[::1]:7890", "http://[::1]:7890", true},
		{"127.0.0.1:7890", "", false},
		{"invalid", "", true},
	} {
		info := parseWindowsProxy(tc.enabled, tc.server)
		if info.ProxyURL != tc.want || info.ProxyEnabled != (tc.want != "") {
			t.Errorf("%q: got %+v, want %q", tc.server, info, tc.want)
		}
	}
}

func TestWindowsRouteSelectsPhysicalDefault(t *testing.T) {
	output := `Active Routes:
 0.0.0.0 0.0.0.0 198.18.0.2 198.18.0.1 0
 0.0.0.0 0.0.0.0 192.168.0.1 192.168.0.10 50
 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.107 25
 0.0.0.0 248.0.0.0 198.18.0.2 198.18.0.1 0
Persistent Routes:
 0.0.0.0 0.0.0.0 192.168.99.1 1`
	info := &EnvironmentInfo{}
	parseWindowsRoutes(output, map[string]string{"198.18.0.1": "Meta", "192.168.1.107": "Ethernet"}, info)
	if info.GatewayIP != "192.168.1.1" || info.ActiveInterface != "Ethernet" || !info.HasTUN {
		t.Fatalf("wrong default route: %+v", info)
	}
}
