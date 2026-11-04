package geoip

import (
	"net"
)

var (
	_, cgnatNet, _   = net.ParseCIDR("100.64.0.0/10")
	_, fakeIPNet, _  = net.ParseCIDR("198.18.0.0/15")
	_, cfNet1, _     = net.ParseCIDR("104.16.0.0/12")
	_, cfNet2, _     = net.ParseCIDR("172.64.0.0/13")
	_, googleNet1, _ = net.ParseCIDR("142.250.0.0/15")
	_, googleNet2, _ = net.ParseCIDR("172.217.0.0/16")
	_, gcoreNet, _   = net.ParseCIDR("109.61.127.0/24")
)

func MatchBuiltinRule(ip net.IP) (*GeoLocation, bool) {
	if ip == nil {
		return nil, false
	}
	if ip.IsLoopback() {
		return &GeoLocation{
			Country: "[本机]",
			City:    "Loopback 本地回环",
		}, true
	}
	if ip.IsPrivate() {
		return &GeoLocation{
			Country: "[局域网]",
			City:    "本地局域网 / 家庭网关",
		}, true
	}
	if cgnatNet != nil && cgnatNet.Contains(ip) {
		return &GeoLocation{
			Country: "[局端]",
			City:    "运营商城域网汇聚网关 (CGNAT)",
			Org:     "Carrier Grade NAT",
		}, true
	}
	if fakeIPNet != nil && fakeIPNet.Contains(ip) {
		return &GeoLocation{
			Country: "[代理]",
			City:    "Clash/Surge TUN 虚拟网卡 (Fake-IP)",
			Org:     "RFC 2544 Benchmark",
		}, true
	}
	if gcoreNet != nil && gcoreNet.Contains(ip) {
		return &GeoLocation{
			Country: "韩国",
			City:    "仁川",
			ASN:     "AS199524",
			Org:     "G-Core Labs S.A.",
		}, true
	}
	if (cfNet1 != nil && cfNet1.Contains(ip)) || (cfNet2 != nil && cfNet2.Contains(ip)) {
		return &GeoLocation{
			Country: "美国",
			City:    "加利福尼亚",
			ASN:     "AS13335",
			Org:     "Cloudflare Anycast",
		}, true
	}
	if (googleNet1 != nil && googleNet1.Contains(ip)) || (googleNet2 != nil && googleNet2.Contains(ip)) {
		return &GeoLocation{
			Country: "美国",
			City:    "加利福尼亚",
			ASN:     "AS15169",
			Org:     "Google LLC",
		}, true
	}
	return nil, false
}
