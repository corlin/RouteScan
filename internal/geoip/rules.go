package geoip

import (
	"net"
)

var (
	_, cgnatNet, _ = net.ParseCIDR("100.64.0.0/10")
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
	return nil, false
}
